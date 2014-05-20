/* module which returns true if string, file or host field are too large */
/* example:      %truncated message : log file /var/log/too-long-message */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct truncated_data {
  char o_name[IDSA_M_NAME];
  int o_number;
};
typedef struct truncated_data TRUNCATE;

/****************************************************************************/
/* parses:  name and drops it into the data structure                       */

static int truncated_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TRUNCATE * o)
{
  IDSA_MEX_TOKEN *token;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  strncpy(o->o_name, token->t_buf, IDSA_M_NAME);
  o->o_name[IDSA_M_NAME - 1] = '\0';
  o->o_number = idsa_resolve_request(idsa_resolve_code(o->o_name));

  return 0;
}

/****************************************************************************/
/* Does       : Create a test instance                                      */

static void *truncated_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  TRUNCATE *o;

  o = malloc(sizeof(TRUNCATE));
  if (o == NULL) {
    idsa_chain_error_malloc(c, sizeof(TRUNCATE));
    return NULL;
  }

  if (truncated_parse(m, c, o)) {
    free(o);
    o = NULL;
  }

  return o;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */
/*              In this example all instances are the same, so we always    */
/*              return equal (0)                                            */

static int truncated_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  TRUNCATE p;
  TRUNCATE *o, *q;
  int result;

  o = t;
  q = &p;

  if (truncated_parse(m, c, q)) {
    return -1;
  }

  result = strcmp(o->o_name, q->o_name);

  return result;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int truncated_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  char buffer[IDSA_M_MESSAGE];
  TRUNCATE *o;
  IDSA_UNIT *unit;
  unsigned int type;
  int current, limit, result;

  result = 0;
  o = t;

  if (o->o_number < idsa_request_count()) {
    unit = idsa_event_unitbynumber(q, o->o_number);
  } else {
    unit = idsa_event_unitbyname(q, o->o_name);
  }

  if (unit == NULL) {
    return result;
  }

  type = idsa_unit_type(unit);

  switch (type) {
  case IDSA_T_STRING:
  case IDSA_T_FILE:
  case IDSA_T_HOST:
    limit = idsa_type_size(type);
    current = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
#ifdef TRACE
    fprintf(stderr, "truncated_test_do(): limit=%d, current=%d\n", limit, current);
#endif
    if (current + 1 >= limit) {
      result = 1;
    }
  default:
    break;
  }

  return result;
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void truncated_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct TRUNCATE *o;

  o = t;

  if (o != NULL) {
    free(o);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_truncated(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "truncated", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &truncated_test_start;
    result->test_cache = &truncated_test_cache;
    result->test_do = &truncated_test_do;
    result->test_stop = &truncated_test_stop;
  }

  return result;
}
