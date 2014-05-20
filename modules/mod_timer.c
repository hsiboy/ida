/*
 * usage in rule head: %timer name         # returns true if named timer is running
 * usage in rule body: timer name [value]  # set named timer to run for value seconds
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

#include <idsa_internal.h>

/****************************************************************************/

static int time_position = 0;

/****************************************************************************/

struct time_value {
  time_t tv_until;
  char tv_name[IDSA_M_NAME];

  struct time_value *tv_next;
};
typedef struct time_value TIME_VALUE;

struct time_op {
  int to_op;
  unsigned int to_value;

  struct time_value *to_timer;
};
typedef struct time_op TIME_OP;

#define TOP_TEST 0x00
#define TOP_SET  0x01

/****************************************************************************/

static TIME_VALUE *value_find(TIME_VALUE ** g, IDSA_RULE_CHAIN * c, char *name)
{
  TIME_VALUE *value;

  value = *g;
  while (value && strncmp(value->tv_name, name, IDSA_M_NAME - 1)) {
    value = value->tv_next;
  }

  return value;
}

static TIME_VALUE *value_make(TIME_VALUE ** g, IDSA_RULE_CHAIN * c, char *name)
{
  TIME_VALUE *value;

  value = value_find(g, c, name);
  if (value) {
    return value;
  }

  value = malloc(sizeof(TIME_VALUE));
  if (value == NULL) {
    idsa_chain_error_malloc(c, sizeof(TIME_VALUE));
    return NULL;
  }

  value->tv_until = 0;
  strncpy(value->tv_name, name, IDSA_M_NAME - 1);
  value->tv_name[IDSA_M_NAME - 1] = '\0';

  value->tv_next = *g;
  *g = value;

  return value;
}

static int generate_test(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TIME_VALUE ** g, TIME_OP * o)
{
  IDSA_MEX_TOKEN *token;

  o->to_op = TOP_TEST;
  o->to_value = 0;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  o->to_timer = value_make(g, c, token->t_buf);
  if (o->to_timer == NULL) {
    return -1;
  }

  return 0;
}

static int generate_action(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TIME_VALUE ** g, TIME_OP * o)
{
  IDSA_MEX_TOKEN *token;

  o->to_op = TOP_SET;
  o->to_value = 0;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }
  o->to_timer = value_make(g, c, token->t_buf);
  if (o->to_timer == NULL) {
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
  o->to_value = atoi(token->t_buf);

  return 0;
}

static int operation_compare(TIME_OP * a, TIME_OP * b)
{
  /* FIXME: makes me feel queasy for some reason */
  return memcmp(a, b, sizeof(TIME_OP));
}

/****************************************************************************/

static void *time_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  TIME_OP *o;

  o = malloc(sizeof(TIME_OP));
  if (o == NULL) {
    idsa_chain_error_malloc(c, sizeof(TIME_OP));
    return NULL;
  }

  if (generate_test(m, c, g, o)) {
    free(o);
    return NULL;
  }

  return o;
}

static int time_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  TIME_OP o;

  if (generate_test(m, c, g, &o)) {
    return -1;
  }

  return operation_compare(t, &o);
}

static void time_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  TIME_OP *o;
  o = t;

  if (o) {
    o->to_timer = NULL;
    free(o);
  }
}

static int time_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  TIME_OP *o;
  TIME_VALUE *v;
  time_t time_now;
  IDSA_UNIT *time_unit;

  /* get hold of time associated with event */
  time_unit = idsa_event_unitbynumber(q, time_position);
  if (time_unit == NULL) {
    return 0;
  }
  if (idsa_unit_get(time_unit, &time_now, sizeof(time_t)) != sizeof(time_t)) {
    return 0;
  }

  /* get hold of timer */
  o = t;
  v = o->to_timer;

  /* has it expired ? */
  if (time_now > v->tv_until) {
    return 0;
  }

  /* timer running, return true */
  return 1;
}

/****************************************************************************/

static void *time_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  TIME_OP *o;

  o = malloc(sizeof(TIME_OP));
  if (o == NULL) {
    idsa_chain_error_malloc(c, sizeof(TIME_OP));
    return NULL;
  }

  if (generate_action(m, c, g, o)) {
#ifdef TRACE
    fprintf(stderr, "time_action_start(): generate_action failed\n");
#endif
    free(o);
    return NULL;
  }

  return o;
}

static int time_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  TIME_OP o;

  if (generate_action(m, c, g, &o)) {
#ifdef TRACE
    fprintf(stderr, "time_action_cache(): generate_action failed\n");
#endif
    return -1;
  }

  return operation_compare(a, &o);
}

static void time_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  TIME_OP *o;
  o = a;

  if (o) {
    o->to_timer = NULL;
    free(o);
  }
}

static int time_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  TIME_OP *o;
  TIME_VALUE *v;

  o = a;
  v = o->to_timer;

#ifdef TRACE
  fprintf(stderr, "time_action_do(): old value for <%s> is <%u>\n", v->tv_name, v->tv_until);
#endif

  if (o->to_value) {		/* nonzero value lets timer run until some time in the future */
    v->tv_until = time(NULL) + o->to_value;
  } else {			/* zero resets it and saves us a system call */
    v->tv_until = 0;
  }

#ifdef TRACE
  fprintf(stderr, "time_action_do(): new value for <%s> is <%u>\n", v->tv_name, v->tv_until);
#endif

  return 0;
}

/****************************************************************************/

static void *time_global_start(IDSA_RULE_CHAIN * c)
{
  TIME_VALUE **pointer;

  if (time_position == 0) {
    /* WARNING: safety issues if concurrent assignments don't yield the consistent value */
    time_position = idsa_resolve_request(IDSA_Q_TIME);
  }

  pointer = malloc(sizeof(TIME_VALUE *));
  if (pointer == NULL) {
    idsa_chain_error_malloc(c, sizeof(TIME_VALUE *));
    return NULL;
  }

  *pointer = NULL;

  return pointer;
}

static void time_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  TIME_VALUE **pointer;
  TIME_VALUE *alpha, *beta;

  pointer = g;

  if (pointer) {
    alpha = *pointer;
    while (alpha) {
      beta = alpha;
      alpha = alpha->tv_next;
      free(beta);
    }
    free(pointer);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_timer(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "timer", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &time_global_start;
    result->global_stop = &time_global_stop;

    result->test_start = &time_test_start;
    result->test_cache = &time_test_cache;
    result->test_do = &time_test_do;
    result->test_stop = &time_test_stop;

    result->action_start = &time_action_start;
    result->action_cache = &time_action_cache;
    result->action_do = &time_action_do;
    result->action_stop = &time_action_stop;
  }

  return result;
}
