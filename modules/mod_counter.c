/*
 * Module to implement a counter. Can be tested in rule head and set in rule body
 *
 *
 * usage in rule head: %counter name [value] 
 * usage in rule body: counter inc|dec|set [value]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <idsa_internal.h>

/****************************************************************************/

struct count_value {
  unsigned int cv_value;
  char cv_name[IDSA_M_NAME];

  struct count_value *cv_next;
};
typedef struct count_value COUNT_VALUE;

struct count_op {
  int co_op;
  unsigned int co_value;

  struct count_value *co_counter;
};
typedef struct count_op COUNT_OP;

#define COP_SET 0x00
#define COP_INC 0x01
#define COP_DEC 0x02

#define COP_GRT 0x10
#define COP_EQL 0x20
#define COP_SML 0x30

/****************************************************************************/

static COUNT_VALUE *value_find(COUNT_VALUE ** g, IDSA_RULE_CHAIN * c, char *name)
{
  COUNT_VALUE *value;

  value = *g;
  while (value && strncmp(value->cv_name, name, IDSA_M_NAME - 1)) {
    value = value->cv_next;
  }

  return value;
}

static COUNT_VALUE *value_make(COUNT_VALUE ** g, IDSA_RULE_CHAIN * c, char *name)
{
  COUNT_VALUE *value;

  value = value_find(g, c, name);
  if (value) {
    return value;
  }

  value = malloc(sizeof(COUNT_VALUE));
  if (value == NULL) {
    idsa_chain_error_malloc(c, sizeof(COUNT_VALUE));
    return NULL;
  }

  value->cv_value = 0;
  strncpy(value->cv_name, name, IDSA_M_NAME - 1);
  value->cv_name[IDSA_M_NAME - 1] = '\0';

  value->cv_next = *g;
  *g = value;

  return value;
}

static int grab_test(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, COUNT_VALUE ** g, COUNT_OP * o)
{
  IDSA_MEX_TOKEN *token;

  o->co_op = COP_GRT;
  o->co_value = 0;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  o->co_counter = value_make(g, c, token->t_buf);
  if (o->co_counter == NULL) {
    return -1;
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    return 0;
  }

  if (!isdigit(token->t_buf[0])) {
    idsa_mex_unget(m, token);
    return 0;
  }

  o->co_value = atoi(token->t_buf);
  return 0;
}

static int grab_action(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, COUNT_VALUE ** g, COUNT_OP * o)
{
  IDSA_MEX_TOKEN *token;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  o->co_counter = value_make(g, c, token->t_buf);
  if (o->co_counter == NULL) {
    return -1;
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  switch (token->t_buf[0]) {
  case 'i':
    o->co_op = COP_INC;
    o->co_value = 1;
    break;
  case 'd':
    o->co_op = COP_DEC;
    o->co_value = 1;
    break;
  case 's':
    o->co_op = COP_SET;
    o->co_value = 0;
    break;
  default:
    idsa_chain_error_usage(c, "unknown operation \"%s\" for counter module", token->t_buf);
    return -1;
    break;
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    return 0;
  }

  if (!isdigit(token->t_buf[0])) {
    idsa_mex_unget(m, token);
    return 0;
  }

  o->co_value = atoi(token->t_buf);
  return 0;
}

static int operation_compare(COUNT_OP * a, COUNT_OP * b)
{
  /* FIXME: makes me feel queasy for some reason */
  return memcmp(a, b, sizeof(COUNT_OP));
}

/****************************************************************************/

static void *count_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  COUNT_OP *o;

  o = malloc(sizeof(COUNT_OP));
  if (o == NULL) {
    idsa_chain_error_malloc(c, sizeof(COUNT_OP));
    return NULL;
  }

  if (grab_test(m, c, g, o)) {
    free(o);
    return NULL;
  }

  return o;
}

static int count_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  COUNT_OP o;

  if (grab_test(m, c, g, &o)) {
    return -1;
  }

  return operation_compare(t, &o);
}

static void count_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  COUNT_OP *o;
  o = t;

  if (o) {
    o->co_counter = NULL;
    free(o);
  }
}

static int count_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  COUNT_OP *o;
  COUNT_VALUE *v;

  o = t;
  v = o->co_counter;

  switch (o->co_op) {
  case COP_GRT:
    return (v->cv_value > o->co_value) ? 1 : 0;
  case COP_EQL:
    return (v->cv_value == o->co_value) ? 1 : 0;
  case COP_SML:
    return (v->cv_value < o->co_value) ? 1 : 0;
  }

  return 0;
}

/****************************************************************************/

static void *count_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  COUNT_OP *o;

  o = malloc(sizeof(COUNT_OP));
  if (o == NULL) {
    idsa_chain_error_malloc(c, sizeof(COUNT_OP));
    return NULL;
  }

  if (grab_action(m, c, g, o)) {
#ifdef TRACE
    fprintf(stderr, "count_action_start(): grab_action failed\n");
#endif
    free(o);
    return NULL;
  }

  return o;
}

static int count_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  COUNT_OP o;

  if (grab_action(m, c, g, &o)) {
#ifdef TRACE
    fprintf(stderr, "count_action_cache(): grab_action failed\n");
#endif
    return -1;
  }

  return operation_compare(a, &o);
}

static void count_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  COUNT_OP *o;
  o = a;

  if (o) {
    o->co_counter = NULL;
    free(o);
  }
}

static int count_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  COUNT_OP *o;
  COUNT_VALUE *v;

  o = a;
  /* if(o->co_counter==NULL) abort(); */
  v = o->co_counter;

#ifdef TRACE
  fprintf(stderr, "count_action_do(): old value for <%s> is <%u>\n", v->cv_name, v->cv_value);
#endif

  switch (o->co_op) {
  case COP_INC:
    v->cv_value += o->co_value;
    if (v->cv_value < o->co_value) {	/* disallow wraparound */
      v->cv_value = UINT_MAX;
    }
    break;
  case COP_DEC:
    if (v->cv_value > o->co_value) {
      v->cv_value -= o->co_value;
    } else {			/* disallow wraparound */
      v->cv_value = 0;
    }
    break;
  case COP_SET:
    v->cv_value = o->co_value;
    break;
  }

#ifdef TRACE
  fprintf(stderr, "count_action_do(): new value for <%s> is <%u>\n", v->cv_name, v->cv_value);
#endif

  return 0;
}

/****************************************************************************/

static void *count_global_start(IDSA_RULE_CHAIN * c)
{
  COUNT_VALUE **pointer;

  pointer = malloc(sizeof(COUNT_VALUE *));
  if (pointer == NULL) {
    idsa_chain_error_malloc(c, sizeof(COUNT_VALUE *));
    return NULL;
  }

  *pointer = NULL;

  return pointer;
}

static void count_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  COUNT_VALUE **pointer;
  COUNT_VALUE *alpha, *beta;

  pointer = g;

  if (pointer) {
    alpha = *pointer;
    while (alpha) {
      beta = alpha;
      alpha = alpha->cv_next;
      free(beta);
    }
    free(pointer);
  }
}


/****************************************************************************/

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_counter(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "counter", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &count_global_start;
    result->global_stop = &count_global_stop;

    result->test_start = &count_test_start;
    result->test_cache = &count_test_cache;
    result->test_do = &count_test_do;
    result->test_stop = &count_test_stop;

    result->action_start = &count_action_start;
    result->action_cache = &count_action_cache;
    result->action_do = &count_action_do;
    result->action_stop = &count_action_stop;
  }

  return result;
}

/*
int main (void){
  printf("hello world\n");
  exit(0);
}
*/
