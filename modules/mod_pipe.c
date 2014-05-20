/* usage: %pipe command [, failopen] [, failclosed] [, timeout value] */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <idsa_internal.h>

#define DEFAULT_TIMEOUT "2.5"
#define FAIL_READS        10
#define SETUP_WAIT         2	/* time to wait at start to let child sort itself out */

/****************************************************************************/

struct pipe_data {
  int p_failopen;
  struct timeval p_timeout;
  int p_fail;

  IDSA_EVENT *p_event;

  int p_fd;
  pid_t p_pid;
  char *p_command;
};

/****************************************************************************/

static int pipe_strexec(char *s);
static void pipe_free(struct pipe_data *pd);
static struct pipe_data *pipe_new(IDSA_RULE_CHAIN * c, char *command, char *timeout, int failopen);

/****************************************************************************/

static void *pipe_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  IDSA_MEX_TOKEN *token;
  char *command, *timeout;
  int failopen;

  failopen = 0;
  command = NULL;
  timeout = NULL;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }
  command = token->t_buf;

  token = idsa_mex_get(m);
  while (token && token->t_id == IDSA_PARSE_COMMA) {
    token = idsa_mex_get(m);
    if (token) {
      if (!strcmp("timeout", token->t_buf)) {
	token = idsa_mex_get(m);
	if (token == NULL) {
	  idsa_chain_error_mex(c, m);
	  return NULL;
	}
	timeout = token->t_buf;
      } else if (!strcmp("failopen", token->t_buf)) {
	failopen = 1;
      } else if (!strcmp("failclosed", token->t_buf)) {
	failopen = 0;
      } else {
	idsa_chain_error_usage(c, "unknown option \"%s\" for pipe module on line %d", token->t_buf, token->t_line);
	return NULL;
      }
      /* try to get next comma */
      token = idsa_mex_get(m);
    }
  }

  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  idsa_mex_unget(m, token);

  return pipe_new(c, command, timeout, failopen);
}

static int pipe_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  IDSA_MEX_TOKEN *token;
  struct pipe_data *pd;
  char *command;
  int result;

  pd = t;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  command = token->t_buf;

  result = strcmp(pd->p_command, command);
  if (result != 0) {		/* no hit */
    return result;
  }

  token = idsa_mex_peek(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  if (token->t_id == IDSA_PARSE_COMMA) {	/* safety check */
    idsa_chain_error_usage(c, "options for \"pipe %s\" can only be specified at the first mention", command);
    return -1;
  }

  return 0;
}

static int pipe_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct pipe_data *pd;
  int result;
  fd_set fs;
  struct timeval tv;
  char buffer[IDSA_M_MESSAGE];
  int i;
  int should_write, write_result, want_write, have_written;
  int read_result, want_read, have_read, copied_bytes;

  pd = t;

  result = pd->p_failopen;
  tv = pd->p_timeout;

  if (pd->p_fail) {		/* attempt to clean out things */
    for (i = 0; i < FAIL_READS; i++) {
      sched_yield();

#ifdef MSG_NOSIGNAL
      read_result = recv(pd->p_fd, buffer, IDSA_M_MESSAGE, MSG_NOSIGNAL);
#else
      read_result = read(pd->p_fd, buffer, IDSA_M_MESSAGE);
#endif
      switch (read_result) {
      case -1:
	if (errno == EAGAIN) {	/* if would block we assume cleaned out */
	  pd->p_fail = 0;
	}
	break;
      case 0:
	i = FAIL_READS;
	pd->p_fail = 1;
	break;
      default:
	pd->p_fail = 1;
	break;
      }
    }
  }

  if (pd->p_fail == 0) {	/* ok */
    pd->p_fail = 1;		/* assume failure */

    /* try to write something */
    should_write = idsa_event_tobuffer(q, buffer, IDSA_M_MESSAGE);
    if (should_write <= 0) {	/* internal error */
      return result;
    }
    want_write = 1;
    have_written = 0;
    do {
#ifdef MSG_NOSIGNAL
      write_result = send(pd->p_fd, buffer + have_written, should_write - have_written, MSG_NOSIGNAL);
#else
      write_result = write(pd->p_fd, buffer + have_written, should_write - have_written);
#endif
      switch (write_result) {
      case -1:
	switch (errno) {
	case EAGAIN:
	case EINTR:
	  break;
	default:
	  want_write = 0;
	  break;
	}
	break;
      case 0:
	break;
      default:
	have_written += write_result;
	if (have_written >= should_write) {
	  want_write = 0;
	}
	break;
      }

      if (want_write) {
	FD_ZERO(&fs);
	FD_SET(pd->p_fd, &fs);
	switch (select(pd->p_fd + 1, NULL, &fs, NULL, &tv)) {
	case -1:
	  switch (errno) {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    want_write = 0;
	    break;
	  }
	  break;
	case 0:
	  want_write = 0;
	  break;
	default:
	  break;
	}
      }
    } while (want_write);

    /* try to read something */
    if (have_written == should_write) {	/* have written event */
      have_read = 0;
      want_read = 1;
      copied_bytes = -1;
      do {
#ifdef MSG_NOSIGNAL
	read_result = recv(pd->p_fd, buffer + have_read, IDSA_M_MESSAGE - have_read, MSG_NOSIGNAL);
#else
	read_result = read(pd->p_fd, buffer + have_read, IDSA_M_MESSAGE - have_read);
#endif
	switch (read_result) {
	case -1:
	  switch (errno) {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    want_read = 0;
	    break;
	  }
	  break;
	case 0:
	  /* EOF */
	  want_read = 0;
	  break;
	default:
	  have_read += read_result;
	  copied_bytes = idsa_event_frombuffer(pd->p_event, buffer, have_read);
	  if (copied_bytes > 0) {
	    want_read = 0;
	  }

	  break;
	}

	if (want_read) {
	  FD_ZERO(&fs);
	  FD_SET(pd->p_fd, &fs);
	  switch (select(pd->p_fd + 1, &fs, NULL, NULL, &tv)) {
	  case -1:
	    switch (errno) {
	    case EAGAIN:
	    case EINTR:
	      break;
	    default:
	      want_read = 0;
	      break;
	    }
	    break;
	  case 0:
	    want_read = 0;
	    break;
	  default:
	    break;
	  }
	}
      } while (want_read);

      if (copied_bytes == have_read) {
	if (idsa_reply_result(pd->p_event) == IDSA_L_DENY) {
	  result = 0;
	} else {
	  result = 1;
	}
	pd->p_fail = 0;
      }				/* end of successful result */
    }				/* end of read attempt */
  }
  /* end of write attempt */
  if (pd->p_fail) {		/* still error, let other side know */
    kill(pd->p_pid, SIGINT);
  }

  return result;
}

static void pipe_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct pipe_data *pd;

  pd = t;

  if (pd) {
    pipe_free(pd);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_pipe(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "pipe", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &pipe_test_start;
    result->test_cache = &pipe_test_cache;
    result->test_do = &pipe_test_do;
    result->test_stop = &pipe_test_stop;
  }

  return result;
}

/****************************************************************************/

static struct pipe_data *pipe_new(IDSA_RULE_CHAIN * c, char *command, char *timeout, int failopen)
{
  struct pipe_data *pd;
  int pp[2];
  int errfd;
  int flags;
  int status;
  char *tptr;
  char tbuf[7];
  int i;

  pd = malloc(sizeof(struct pipe_data));
  if (pd == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct pipe_data));
    return NULL;
  }

  pd->p_timeout.tv_sec = atoi(timeout ? timeout : DEFAULT_TIMEOUT);

  tptr = strchr(timeout ? timeout : DEFAULT_TIMEOUT, '.');
  if (tptr) {
    tptr++;
    for (i = 0; (i < 6) && tptr[i] != '\0'; i++) {
      tbuf[i] = tptr[i];
    }
    for (; i < 6; i++) {
      tbuf[i] = '0';
    }
    tbuf[6] = '\0';
    pd->p_timeout.tv_usec = atoi(tbuf);
  } else {
    pd->p_timeout.tv_usec = 0;
  }

#ifdef TRACE
  fprintf(stderr, "idsa_module_load_pipe(): timeouts are %d.%06dus\n", (int) pd->p_timeout.tv_sec, (int) pd->p_timeout.tv_usec);
#endif

  pd->p_failopen = failopen;

  pd->p_event = NULL;
  pd->p_fd = (-1);
  pd->p_pid = 0;
  pd->p_command = NULL;

  pd->p_event = idsa_event_new(0);
  if (pd->p_event == NULL) {
    /* WARNING: size is a lie */
    idsa_chain_error_malloc(c, IDSA_M_MESSAGE);
    pipe_free(pd);
    return NULL;
  }

  pd->p_command = strdup(command);
  if (pd->p_command == NULL) {
    idsa_chain_error_malloc(c, strlen(command) + 1);
    pipe_free(pd);
    return NULL;
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pp)) {
    idsa_chain_error_system(c, errno, "unable to create unix domain pipe for \"%s\"", pd->p_command);
    pipe_free(pd);
    return NULL;
  }

  pd->p_pid = fork();
  switch (pd->p_pid) {
  case -1:
    idsa_chain_error_system(c, errno, "unable to fork \"%s\"", pd->p_command);
    pipe_free(pd);
    close(pp[0]);
    close(pp[1]);
    return NULL;		/* failure */
  case 0:			/* in child */

    close(pp[0]);

    if (pp[1] != STDIN_FILENO) {
      if (dup2(pp[1], STDIN_FILENO) != STDIN_FILENO) {	/* failure */
	/* WARNING: abuse of return code */
	exit(errno);
      }
    }
    if (pp[1] != STDOUT_FILENO) {
      if (dup2(pp[1], STDOUT_FILENO) != STDOUT_FILENO) {	/* failure */
	/* WARNING: abuse of return code */
	exit(errno);
      }
    }
    if (pp[1] >= STDERR_FILENO) {
      close(pp[1]);
    }

    close(STDERR_FILENO);
    errfd = open("/dev/null", O_WRONLY);
    if ((errfd > 0) && (errfd != STDERR_FILENO)) {
      dup2(errfd, STDERR_FILENO);
      close(errfd);
    }

    pipe_strexec(pd->p_command);
    /* WARNING: abuse of return code */
    exit(errno);

    break;
  default:			/* in parent */
    close(pp[1]);
    pd->p_fd = pp[0];

    fcntl(pd->p_fd, F_SETFD, FD_CLOEXEC);

    flags = fcntl(pd->p_fd, F_GETFL, 0);
    if ((flags == (-1))
	|| (fcntl(pd->p_fd, F_SETFL, O_NONBLOCK | flags) == (-1))) {
      idsa_chain_error_system(c, errno, "unable to make pipe to \"%s\" nonblocking", pd->p_command);
      pipe_free(pd);
      return NULL;
    }

    /* yield to child */
    sched_yield();

    if (waitpid(pd->p_pid, &status, WNOHANG) > 0) {	/* found a child or error */
      if (WIFEXITED(status)) {
	idsa_chain_error_system(c, WIFEXITED(status), "unable to to start child \"%s\"", pd->p_command);
      } else {
	idsa_chain_error_internal(c, "unable to to start child \"%s\"", pd->p_command);
      }
      pipe_free(pd);
      return NULL;
    }
    break;
  }

  /* only in parent */

  sleep(SETUP_WAIT);

  return pd;
}

static void pipe_free(struct pipe_data *pd)
{
  int status;

  if (pd) {
    if (pd->p_fd != (-1)) {
      close(pd->p_fd);
      pd->p_fd = (-1);
    }
    if (pd->p_event) {
      idsa_event_free(pd->p_event);
      pd->p_event = NULL;
    }
    if (pd->p_command) {
      free(pd->p_command);
      pd->p_command = NULL;
    }

    /* yield to child */
    sched_yield();

    if (pd->p_pid) {
      /* collect zombie */
      waitpid(pd->p_pid, &status, WNOHANG);
      pd->p_pid = 0;
    }
    free(pd);
  }
}

static int pipe_strexec(char *s)
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
#ifdef TRACE
  fprintf(stderr, "strexec(): <%s> has %d elements\n", s, e);
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
#ifdef TRACE
    fprintf(stderr, "strexec(): execvp(%s,...) failed: %s\n", s, strerror(errno));
#endif
  }
  return -1;
}
