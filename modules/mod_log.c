#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <idsa_internal.h>

struct log_state {
  char s_name[IDSA_M_FILE];	/* name of target */
  off_t s_rotate;		/* rotate: when do we trigger */
  int s_sync;			/* synchronous writes */
  int s_pipe;			/* is a pipe ? */

  int s_fd;
  int s_rd;			/* rotate: alternate descriptor */
  off_t s_have;			/* rotate: how much do we have currently */
  pid_t s_pid;			/* pid of pipe */

  struct log_state *s_next;
};
typedef struct log_state LOG_STATE;

struct log_pointer {
  int p_custom;

  char *p_string;		/* before parse */
  IDSA_PRINT_HANDLE *p_handle;	/* what do we write to p_state */

  struct log_state *p_state;
};
typedef struct log_pointer LOG_POINTER;

/****************************************************************************/

static int idsa_log_open(IDSA_RULE_CHAIN * c, char *name, int flags)
{
  int result;
  mode_t mode;

  mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;

  result = open(name, flags, mode);
  if (result == (-1)) {
    idsa_chain_error_system(c, errno, "unable to open file \"%s\"", name);
  } else {
    fcntl(result, F_SETFD, FD_CLOEXEC);
  }

  return result;
}

static int idsa_log_file(IDSA_RULE_CHAIN * c, LOG_STATE * s)
{
  int flags;

  flags = O_APPEND | O_CREAT | O_WRONLY;
#ifdef O_SYNC
  if (s->s_sync)
    flags |= O_SYNC;
#else
#warning O_SYNC not available, synchronous logging option will not be honoured
#endif

  if (s->s_rotate) {		/* should rotate */
    char buf[IDSA_M_FILE + 3];
    struct stat fst, rst;
    int td;

    snprintf(buf, IDSA_M_FILE + 2, "%s-1", s->s_name);
    buf[IDSA_M_FILE + 2] = '\0';
    s->s_fd = idsa_log_open(c, buf, flags);
    if (fstat(s->s_fd, &fst)) {
      idsa_chain_error_system(c, errno, "unable to stat \"%s\"", buf);
      return -1;
    }

    snprintf(buf, IDSA_M_FILE + 2, "%s-2", s->s_name);
    buf[IDSA_M_FILE + 2] = '\0';
    s->s_rd = idsa_log_open(c, buf, flags);
    if (fstat(s->s_rd, &rst)) {
      idsa_chain_error_system(c, errno, "unable to stat \"%s\"", buf);
      return -1;
    }

    /* work with newest file */
    if (rst.st_mtime > fst.st_mtime) {
      td = s->s_rd;
      s->s_rd = s->s_fd;
      s->s_fd = td;

      s->s_have = rst.st_size;
    } else {
      s->s_have = fst.st_size;
    }

  } else {
    s->s_fd = idsa_log_open(c, s->s_name, flags);;
    if (s->s_fd < 0) {
      return -1;
    }
  }

  return 0;
}

static int idsa_log_strexec(char *s)
{
  int i, j, e;
  char **a;

  i = 0;
  j = 1;
  e = 0;
  while (s[i] != '\0') {
    if (isspace(s[i])) {
      j = 1;
    } else {
      if (j) {
	e++;
	j = 0;
      }
    }
    i++;
  }
#ifdef DEBUG
  fprintf(stderr, "log_strexec(): \"%s\" has %d elements\n", s, e);
#endif
  e++;

  a = malloc(sizeof(char *) * e);
  if (a) {
    i = 0;
    j = 1;
    e = 0;
    while (s[i] != '\0') {
      if (isspace(s[i])) {
	s[i] = '\0';
	j = 1;
      } else {
	if (j) {
	  a[e] = s + i;
	  e++;
	  j = 0;
	}
      }
      i++;
    }
    a[e] = NULL;
    execvp(s, a);
#ifdef DEBUG
    fprintf(stderr, "log_strexec(): execvp(%s,...) failed: %s\n", s, strerror(errno));
#endif
  }
  return -1;
}


static int idsa_log_pipe(IDSA_RULE_CHAIN * c, LOG_STATE * s)
{
  int p[2];
  int status;
  int flags;

  if (s->s_rotate) {
    idsa_chain_error_usage(c, "pipes do not allow rotation");
    return -1;
  }

  if (pipe(p)) {
    idsa_chain_error_system(c, errno, "unable to create pipe for \"%s\"", s->s_name);
    return -1;
  }

  s->s_pid = fork();
  switch (s->s_pid) {
  case -1:
    idsa_chain_error_system(c, errno, "unable to fork \"%s\"", s->s_name);
    close(p[0]);
    close(p[1]);
    return -1;
    break;
  case 0:			/* in child */

    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    close(p[1]);

    if (p[0] != STDIN_FILENO) {
      if (dup2(p[0], STDIN_FILENO) != STDIN_FILENO) {	/* failure */
	/* WARNING: abuse of return code */
	exit(errno);
      } else {
	close(p[0]);
      }
    }

    idsa_log_strexec(s->s_name);
    /* WARNING: abuse return code again */
    exit(errno);

    break;
  default:			/* in parent */
    close(p[0]);
    s->s_fd = p[1];

    /* yield to child */
    sched_yield();

    if (waitpid(s->s_pid, &status, WNOHANG) > 0) {	/* child failed somehow */
      if (WIFEXITED(status)) {
	idsa_chain_error_system(c, WEXITSTATUS(status), "unable to start child process \"%s\"", s->s_name);
      } else if (WIFSIGNALED(status)) {
	idsa_chain_error_internal(c, "child process \"%s\" killed by signal %d", s->s_name, WTERMSIG(status));
      }
      return -1;
    }

    if (s->s_sync == 0) {
      flags = fcntl(s->s_fd, F_GETFL, 0);
      if ((flags == (-1)) || fcntl(s->s_fd, F_SETFL, O_NONBLOCK | flags)) {
	idsa_chain_error_system(c, errno, "unable to make pipe to \"%s\" nonblocking", s->s_name);
	return -1;
      }
    }

    break;
  }

  return 0;
}

/****************************************************************************/

static void delete_state(IDSA_RULE_CHAIN * c, LOG_STATE * s)
{
  if (s == NULL) {
    return;
  }

  if (s->s_fd >= 0) {
    close(s->s_fd);
    s->s_fd = (-1);
  }
  if (s->s_rd >= 0) {
    close(s->s_rd);
    s->s_rd = (-1);
  }

  s->s_next = NULL;
  free(s);
}

static int equivalent_state(LOG_STATE * active, LOG_STATE * proposed)
{
  if (active->s_pipe != proposed->s_pipe) {
    return 1;
  }

  /* WARNING: The comparisions are asymetric, allowing user to omit options on second occurance */
  if (proposed->s_rotate) {
    if (active->s_rotate != proposed->s_rotate) {
      return 1;
    }
  }

  if (proposed->s_sync) {
    if (active->s_sync != proposed->s_sync) {
      return 1;
    }
  }

  return 0;
}

static int activate_state(IDSA_RULE_CHAIN * c, LOG_STATE * s)
{
  return (s->s_pipe) ? idsa_log_pipe(c, s) : idsa_log_file(c, s);
}

static LOG_STATE *insert_state(IDSA_RULE_CHAIN * c, void *g, LOG_STATE * s)
{
  /* WARNING: insert_state has side-effect of deleting log state if it already exists */

  LOG_STATE **global;
  LOG_STATE *search;

  global = g;
  search = *global;

  while (search) {
    if (!strcmp(search->s_name, s->s_name)) {
      if (equivalent_state(search, s)) {
	idsa_chain_error_usage(c, "conflicting log options for \"%s\"", search->s_name);
	delete_state(c, s);
	return NULL;
      } else {
	delete_state(c, s);
	return search;
      }
    }
    search = search->s_next;
  }

  /* only reached if this state is new */

  s->s_next = *global;
  *global = s;

  if (activate_state(c, s)) {
    return NULL;
  }

  return s;
}

static LOG_STATE *new_state(IDSA_RULE_CHAIN * c)
{
  LOG_STATE *s;

  s = malloc(sizeof(LOG_STATE));
  if (s == NULL) {
    idsa_chain_error_malloc(c, sizeof(LOG_STATE));
    return NULL;
  }

  s->s_name[0] = '\0';
  s->s_fd = (-1);
  s->s_rd = (-1);
  s->s_have = 0;
  s->s_pid = 0;
  s->s_next = NULL;

  s->s_sync = 0;
  s->s_pipe = 0;
  s->s_rotate = 0;

  return s;
}

/****************************************************************************/

static int activate_pointer(IDSA_RULE_CHAIN * c, LOG_POINTER * p)
{
  if (p->p_string) {
    p->p_handle = p->p_custom ? idsa_print_parse(p->p_string) : idsa_print_format(p->p_string);
  } else {
    p->p_handle = idsa_print_format("internal");
  }

  if (p->p_handle == NULL) {
    idsa_chain_error_usage(c, "unable to initialize output format \"%s\"", p->p_string ? p->p_string : "internal");
    return -1;
  }

  return 0;
}

static LOG_POINTER *new_pointer(IDSA_RULE_CHAIN * c)
{
  LOG_POINTER *p;

  p = malloc(sizeof(LOG_POINTER));
  if (p == NULL) {
    idsa_chain_error_malloc(c, sizeof(LOG_POINTER));
    return NULL;
  }

  p->p_custom = 0;
  p->p_state = NULL;
  p->p_handle = NULL;
  p->p_string = NULL;

  return p;
}

static void delete_pointer(IDSA_RULE_CHAIN * c, LOG_POINTER * p)
{
  if (p == NULL) {
    return;
  }

  if (p->p_string) {
    free(p->p_string);
    p->p_string = NULL;
  }

  if (p->p_handle) {
    idsa_print_free(p->p_handle);
    p->p_handle = NULL;
  }

  p->p_state = NULL;

  free(p);
}

/****************************************************************************/

static int parse_both(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, LOG_POINTER * p, LOG_STATE * s)
{
  IDSA_MEX_TOKEN *type, *target, *token;

  /* initialize pointer */
  p->p_string = NULL;
  p->p_handle = NULL;
  p->p_state = NULL;

  /* initialize state */
  s->s_fd = (-1);
  s->s_rd = (-1);
  s->s_have = 0;
  s->s_pid = 0;
  s->s_next = NULL;

  /* defaults */
  s->s_sync = 0;
  s->s_pipe = 0;
  s->s_rotate = 0;

  type = idsa_mex_get(m);
  target = idsa_mex_get(m);

  if ((type == NULL) || (target == NULL)) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  if (strcmp(type->t_buf, "file") == 0) {
    s->s_pipe = 0;
  } else if (strcmp(type->t_buf, "pipe") == 0) {
    s->s_pipe = 1;
  } else {
    idsa_chain_error_usage(c, "unknown log type \"%s\"", type->t_buf);
    return -1;
  }

  if (target->t_buf[0] != '/') {
    idsa_chain_error_usage(c, "log destination \"%s\" has to be an absolute path", target->t_buf);
    return -1;
  } else {
    strncpy(s->s_name, target->t_buf, IDSA_M_FILE - 1);
    s->s_name[IDSA_M_FILE - 1] = '\0';
  }

  /* collect all the options */
  token = idsa_mex_get(m);
  while (token != NULL) {
    if (token->t_id != IDSA_PARSE_COMMA) {	/* no more options, go back */
      idsa_mex_unget(m, token);
      token = NULL;
    } else {
      token = idsa_mex_get(m);
      if (token) {
	if (strcmp(token->t_buf, "rotate") == 0) {
	  token = idsa_mex_get(m);
	  if (token) {
	    s->s_rotate = atoi(token->t_buf);
	    if (s->s_rotate == 0) {
	      idsa_chain_error_usage(c, "expected a nonzero rotation value instead of \"%s\"", token->t_buf);
	      return -1;
	    }
	  } else {
	    idsa_chain_error_mex(c, m);
	    return -1;
	  }
	} else if (strcmp(token->t_buf, "sync") == 0) {
	  s->s_sync = 1;
	} else if (strcmp(token->t_buf, "custom") == 0) {
	  if (p->p_string) {
	    free(p->p_string);
	    p->p_string = NULL;
	  }
	  token = idsa_mex_get(m);
	  if (token == NULL) {
	    idsa_chain_error_mex(c, m);
	    return -1;
	  }
	  p->p_custom = 1;
	  p->p_string = strdup(token->t_buf);
	  if (p->p_string == NULL) {
	    idsa_chain_error_malloc(c, strlen(token->t_buf) + 1);
	    return -1;
	  }
	} else if (strcmp(token->t_buf, "format") == 0) {
	  if (p->p_string) {
	    free(p->p_string);
	    p->p_string = NULL;
	  }
	  token = idsa_mex_get(m);
	  if (token == NULL) {
	    idsa_chain_error_mex(c, m);
	    return -1;
	  }
	  p->p_custom = 0;
	  p->p_string = strdup(token->t_buf);
	  if (p->p_string == NULL) {
	    idsa_chain_error_malloc(c, strlen(token->t_buf) + 1);
	    return -1;
	  }
	} else {
	  idsa_chain_error_usage(c, "unknown log option \"%s\"", token->t_buf);
	  return -1;
	}
	token = idsa_mex_get(m);
      } else {
	idsa_chain_error_mex(c, m);
	return -1;
      }
    }
  }

  return 0;
}

/****************************************************************************/

void *idsa_log_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  LOG_STATE *s;
  LOG_POINTER *p;

  p = new_pointer(c);
  s = new_state(c);

  if ((p == NULL) || (s == NULL)) {
    if (p != NULL) {
      delete_pointer(c, p);
    }
    if (s != NULL) {
      delete_state(c, s);
    }
    return NULL;
  }

  if (parse_both(m, c, p, s)) {
    delete_pointer(c, p);
    delete_state(c, s);
    return NULL;
  }

  s = insert_state(c, g, s);	/* WARNING: s can get changed */
  if (s == NULL) {
    delete_pointer(c, p);
    return NULL;
  }

  p->p_state = s;

  if (activate_pointer(c, p)) {
    delete_pointer(c, p);
    return NULL;
  }

  return p;
}

int idsa_log_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  LOG_STATE *s, *state;
  LOG_POINTER *p, *pointer;
  int result = (-1);

  pointer = a;
  state = pointer->p_state;

  p = new_pointer(c);
  s = new_state(c);

  if ((p != NULL) && (s != NULL)) {
    if (parse_both(m, c, p, s) == 0) {
      result = strcmp(s->s_name, state->s_name);
      if (result == 0) {

	if (equivalent_state(state, s)) {
	  idsa_chain_error_usage(c, "conflicting log options for \"%s\"", state->s_name);
	  result = (-1);
	} else {
	  /* FIXME: theoretically should consider p->p_custom too */
	  if (p->p_string == NULL) {	/* user did not specify format, be happy with previous */
	    return 0;
	  } else {
	    if (pointer->p_string == NULL) {
	      result = 1;	/* NULL always smaller than something */
	    } else {
	      result = strcmp(p->p_string, pointer->p_string);
	    }
	  }
	}

      }
    }
  }

  if (p != NULL) {
    delete_pointer(c, p);
  }
  if (s != NULL) {
    delete_state(c, s);
  }

  return result;
}

#define BUFFER (8*IDSA_M_MESSAGE)

int idsa_log_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  LOG_POINTER *pointer;
  LOG_STATE *state;
  char buffer[BUFFER];
  int wr, sw;

  pointer = a;
  state = pointer->p_state;

  sw = idsa_print_do(q, pointer->p_handle, buffer, BUFFER);
  if (sw <= 0) {
    idsa_chain_error_internal(c, "nothing to write to \"%s\"", state->s_name);
    return 1;
  }

  wr = write(state->s_fd, buffer, sw);
  if (wr != sw) {
    idsa_chain_error_system(c, errno, "write to \"%s\" failed", state->s_name);
    return 1;
  }

  if (state->s_rotate) {
    state->s_have += sw;
    if (state->s_have >= state->s_rotate) {
      int td;

      td = state->s_fd;
      state->s_fd = state->s_rd;
      state->s_rd = td;
      state->s_have = 0;

      if (ftruncate(state->s_fd, 0)) {
	idsa_chain_error_system(c, errno, "truncate of \"%s\" failed", state->s_name);
	return 1;
      }
    }
  }

  return 0;
}

void idsa_log_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  LOG_POINTER *pointer;

  pointer = a;
  if (pointer) {
    delete_pointer(c, pointer);
  }
}

/****************************************************************************/


void *idsa_log_global_start(IDSA_RULE_CHAIN * c)
{
  LOG_STATE **global;

  global = malloc(sizeof(LOG_STATE *));
  if (global == NULL) {
    idsa_chain_error_malloc(c, sizeof(LOG_STATE *));
    return NULL;
  }

  *global = NULL;

  return global;
}

void idsa_log_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  LOG_STATE **global;
  LOG_STATE *alpha, *beta;

  global = g;

  if (global == NULL) {
    return;
  }

  alpha = *global;
  while (alpha) {
    beta = alpha;
    alpha = alpha->s_next;
    free(beta);
  }
  free(global);
}

/****************************************************************************/

IDSA_MODULE *idsa_module_load_log(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "log", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &idsa_log_global_start;
    result->global_stop = &idsa_log_global_stop;

    result->action_start = &idsa_log_action_start;
    result->action_cache = &idsa_log_action_cache;
    result->action_do = &idsa_log_action_do;
    result->action_stop = &idsa_log_action_stop;
  }

  return result;
}
