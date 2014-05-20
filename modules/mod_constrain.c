/* string constraint test. 
 *
 * usage    %constrain label [:type] name violations [, file path]
 *           constrain label [:type] name count      [, update] [, file path]
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <idsa_internal.h>

#define TABLE_SIZE    256	/* number of chars */
#define TABLE_PRINT   256*8	/* largest size of print buffer */

typedef struct constrain_body {
  char b_name[IDSA_M_NAME];	/* name of constrain "variable" */

  unsigned short b_table[TABLE_SIZE];	/* table of characters */

  char b_file[IDSA_M_FILE];	/* file to save state */
  int b_fd;			/* the corresponding file descriptor */

  struct constrain_body *b_next;	/* linked list (only used at startup) */
} BODY;

typedef struct constrain_ref {
  char r_label[IDSA_M_NAME];	/* attribute/field to examine */

  struct constrain_body *r_body;	/* ptr to "variable" */

  unsigned int r_update;	/* only valid in action: write back changes immediately */
  unsigned int r_count;		/* head: number of differences. body: extra length */
} REF;

/****************************************************************************/

static int constrain_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, BODY ** global, REF * r, int action);

static void constrain_end_body(IDSA_RULE_CHAIN * c, BODY ** global, BODY * b);
static BODY *constrain_start_body(IDSA_RULE_CHAIN * c, BODY ** global, char *name, char *file);

static int constrain_save_file(IDSA_RULE_CHAIN * c, BODY * b);
static int constrain_load_file(IDSA_RULE_CHAIN * c, BODY * b);

/****************************************************************************/

static int constrain_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, BODY ** global, REF * r, int action)
{
  IDSA_MEX_TOKEN *token;
  char *file;
  char *name;

  /* get label */
  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  strncpy(r->r_label, token->t_buf, IDSA_M_NAME - 1);
  r->r_label[IDSA_M_NAME - 1] = '\0';

  /* get name */
  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  /* check if there is a type - if there is ignore it ;) */
  if (token->t_id == IDSA_PARSE_COLON) {
    idsa_mex_get(m);
    token = idsa_mex_get(m);
    if (token == NULL) {
      idsa_chain_error_mex(c, m);
      return -1;
    }
  }
  name = token->t_buf;
  file = NULL;

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": parsing label %s, name %s\n", r->r_label, name);
#endif

  r->r_count = 0;
  r->r_update = 0;
  r->r_body = NULL;

  /* get count */
  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  r->r_count = atoi(token->t_buf);

  /* get options */
  token = idsa_mex_get(m);
  while (token) {
    if (token->t_id != IDSA_PARSE_COMMA) {
      idsa_mex_unget(m, token);
      token = NULL;
    } else {
      token = idsa_mex_get(m);
      if (token == NULL) {
	idsa_chain_error_mex(c, m);
	return -1;
      }
      if (!strcmp("update", token->t_buf)) {
	if (action) {
	  r->r_update = 1;
	} else {
	  idsa_chain_error_usage(c, "option \"%s\" only valid in rule body", token->t_buf);
	  return -1;
	}
      } else if (!strcmp("file", token->t_buf)) {
	token = idsa_mex_get(m);
	if (token == NULL) {
	  idsa_chain_error_mex(c, m);
	  return -1;
	}
	file = token->t_buf;
      } else {
	idsa_chain_error_usage(c, "unknown option \"%s\" for module constrain", token->t_buf);
	return -1;
      }
      token = idsa_mex_get(m);
    }
  }

  r->r_body = constrain_start_body(c, global, name, file);
  if (r->r_body == NULL) {
    return -1;
  }

  return 0;
}

/****************************************************************************/

static void *constrain_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, BODY ** global, int action)
{
  REF *ref;

  ref = malloc(sizeof(REF));
  if (ref == NULL) {
    idsa_chain_error_malloc(c, sizeof(REF));
    return NULL;
  }
#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": malloced %p\n", ref);
#endif

  if (constrain_parse(m, c, global, ref, action)) {
    free(ref);
    return NULL;
  }

  return ref;
}

static int constrain_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, BODY ** global, REF * refx, int action)
{
  REF *refy;
  REF tref;
  int result;

  refy = &tref;

  /* somehow a memcmp here would make me nervous */

  if (constrain_parse(m, c, global, refy, action)) {
    return -1;
  }

  result = strcmp(refy->r_label, refx->r_label);
  if (result) {
    return result;
  }

  if (refy->r_body != refx->r_body) {
    return (refy->r_body > refx->r_body) ? 1 : (-1);
  }

  if (refy->r_count != refx->r_count) {
    return (refy->r_count > refx->r_count) ? 1 : (-1);
  }

  if (refy->r_update != refx->r_update) {
    return (refy->r_update > refx->r_update) ? 1 : (-1);
  }

  return 0;
}

static void constrain_stop(IDSA_RULE_CHAIN * c, BODY ** global, REF * ref)
{
  if (ref != NULL) {
    free(ref);
  }
}

/****************************************************************************/

static void *constrain_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  return constrain_start(m, c, g, 0);
}

static int constrain_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  return constrain_cache(m, c, g, t, 0);
}

static void constrain_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  constrain_stop(c, g, t);
}

/****************************************************************************/

static void *constrain_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  return constrain_start(m, c, g, 1);
}

static int constrain_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  return constrain_cache(m, c, g, a, 1);
}

static void constrain_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  constrain_stop(c, g, a);
}

/****************************************************************************/

static int constrain_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  unsigned char buffer[IDSA_M_MESSAGE];
  IDSA_UNIT *unit;
  REF *ref;
  BODY *b;
  int len, i;
  unsigned delta;

  ref = (REF *) (t);
  b = ref->r_body;

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": ref = %p\n", ref);
#endif

  unit = idsa_event_unitbyname(q, ref->r_label);
  if (unit == NULL) {
    return 0;
  }

  len = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
  if (len <= 0) {
    return 0;
  }

  for (delta = 0, i = 0; i < len; i++) {
    if (b->b_table[buffer[i]] < (i + 1)) {
      delta += (i + 1) - b->b_table[buffer[i]];
    }
  }

  if (delta > ref->r_count) {
    return 1;
  }

  return 0;
}

static int constrain_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  unsigned char buffer[IDSA_M_MESSAGE];
  IDSA_UNIT *unit;
  REF *ref;
  BODY *b;
  int len, i;
  int change;

  ref = (REF *) (a);
  b = ref->r_body;

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": ref = %p\n", ref);
#endif

  unit = idsa_event_unitbyname(q, ref->r_label);
  if (unit == NULL) {
    return 0;
  }

  len = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
  if (len <= 0) {
    return 0;
  }

  change = 0;
  for (i = 0; i < len; i++) {
    if (b->b_table[buffer[i]] < (i + 1)) {
      b->b_table[buffer[i]] = (i + 1) + ref->r_count;
      change = 1;
    }
  }

  if (change && ref->r_update) {
    constrain_save_file(c, b);
  }

  return 0;
}

/****************************************************************************/

void *idsa_constrain_global_start(IDSA_RULE_CHAIN * c)
{
  BODY **global;

  global = malloc(sizeof(BODY *));
  if (global == NULL) {
    idsa_chain_error_malloc(c, sizeof(BODY *));
    return NULL;
  }

  *global = NULL;

  return global;
}

void idsa_constrain_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  BODY **global;
  BODY *alpha, *beta;

  global = g;

  if (global == NULL) {
    return;
  }

  alpha = *global;
  free(global);

  while (alpha) {
    beta = alpha;
    alpha = alpha->b_next;
    constrain_end_body(c, g, beta);
  }
}

/****************************************************************************/

static int constrain_save_file(IDSA_RULE_CHAIN * c, BODY * b)
{
  unsigned int i, j, k;
  char buffer[TABLE_PRINT];

  if (b->b_fd != (-1)) {
    for (i = 0, j = 0; (i < TABLE_SIZE) && (j < TABLE_PRINT); i++) {
      k = snprintf(buffer + j, TABLE_PRINT - j, "%hu ", b->b_table[i]);
      j = (k < 0) ? TABLE_PRINT : (k + j);
    }
    if (j >= TABLE_PRINT) {
      return -1;
    }
    if (j > 0) {
      buffer[j - 1] = '\n';
      if (write(b->b_fd, buffer, j) != j) {
	return -1;
      }
      if (lseek(b->b_fd, 0, SEEK_SET) != j) {
	return -1;
      }
      /* should never be needed, since it only ever grows ? */
      /* if(ftruncate(b->b_fd, j)){ return -1; } */
    }
  }

  return 0;
}

static int constrain_load_file(IDSA_RULE_CHAIN * c, BODY * b)
{
  unsigned int i, j;
  char buffer[TABLE_PRINT];
  struct stat st;

  if (b->b_file[0] != '\0') {
    b->b_fd = open(b->b_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (b->b_fd < 0) {
      idsa_chain_error_system(c, errno, "unable to open file \"%s\"", b->b_file);
      return -1;
    }
    if (fstat(b->b_fd, &st)) {
      idsa_chain_error_system(c, errno, "unable to stat file \"%s\"", b->b_file);
      close(b->b_fd);
      b->b_fd = (-1);
      return -1;
    }
    if (st.st_size > 0) {
      if ((st.st_size >= TABLE_PRINT) || (st.st_size < TABLE_SIZE)) {
	idsa_chain_error_internal(c, "file \"%s\" has an unreasonable size", b->b_file);
	close(b->b_fd);
	b->b_fd = (-1);
	return -1;
      }
      if (read(b->b_fd, buffer, st.st_size) != st.st_size) {
	idsa_chain_error_system(c, errno, "unable to read file \"%s\"", b->b_file);
	close(b->b_fd);
	b->b_fd = (-1);
	return -1;
      }
      lseek(b->b_fd, 0, SEEK_SET);
      buffer[st.st_size - 1] = '\0';
      for (i = 0, j = 0; (i < TABLE_SIZE) && (j < st.st_size); i++) {
	b->b_table[i] = atoi(buffer + j);
#ifdef DEBUG
	fprintf(stderr, __FUNCTION__ ": %c=%d\n", isprint((char) i) ? (char) i : '*', b->b_table[i]);
#endif
	for (; (j < st.st_size) && (buffer[j] != ' '); j++);
	j++;
      }
    }
  }

  return 0;
}

static void constrain_end_body(IDSA_RULE_CHAIN * c, BODY ** global, BODY * b)
{
  if (b) {
    if (b->b_fd != (-1)) {
      constrain_save_file(c, b);
    }
    free(b);
  }
}

static BODY *constrain_start_body(IDSA_RULE_CHAIN * c, BODY ** global, char *name, char *file)
{
  BODY *b;
  unsigned int i;

  b = *global;

  while (b) {
    if (strncmp(name, b->b_name, IDSA_M_NAME - 1)) {
      b = b->b_next;
    } else {
      if (file) {
	if (b->b_file[0] == '\0') {
	  strncpy(b->b_file, file, IDSA_M_FILE - 1);
	  b->b_file[IDSA_M_FILE - 1] = '\0';
	  if (constrain_load_file(c, b)) {
	    return NULL;
	  }
	} else {
	  if (strncmp(b->b_file, file, IDSA_M_FILE - 1)) {
	    idsa_chain_error_usage(c, "can only have a single file name for \"%s\" but have both \"%s\" and \"%s\"", name, file, b->b_file);
	    return NULL;
	  }
	}
      }
      return b;
    }
  }

  /* not found, have to create new */
  b = malloc(sizeof(BODY));
  if (b == NULL) {
    idsa_chain_error_malloc(c, sizeof(BODY));
    return NULL;
  }

  strncpy(b->b_name, name, IDSA_M_NAME - 1);
  b->b_name[IDSA_M_NAME - 1] = '\0';

  for (i = 0; i < TABLE_SIZE; i++) {
    b->b_table[i] = 0;
  }

  b->b_fd = (-1);
  b->b_file[0] = '\0';

  b->b_next = *global;
  *global = b;

  if (file) {
    strncpy(b->b_file, file, IDSA_M_FILE - 1);
    b->b_file[IDSA_M_FILE - 1] = '\0';
    if (constrain_load_file(c, b)) {
      return NULL;
    }
  }

  return b;
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_constrain(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "constrain", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &idsa_constrain_global_start;
    result->global_stop = &idsa_constrain_global_stop;

    result->test_start = &constrain_test_start;
    result->test_cache = &constrain_test_cache;
    result->test_do = &constrain_test_do;
    result->test_stop = &constrain_test_stop;

    result->action_start = &constrain_action_start;
    result->action_cache = &constrain_action_cache;
    result->action_do = &constrain_action_do;
    result->action_stop = &constrain_action_stop;
  }

  return result;
}
