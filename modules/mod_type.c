/* existence test. Will test if an event contains an event with given type
 *
 * usage    %type key type
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

typedef struct type_data {
  char t_key[IDSA_M_NAME];
  unsigned t_type;
} TYPE_DATA;

static int type_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, TYPE_DATA * e)
{
  IDSA_MEX_TOKEN *key, *type;
  unsigned int implicit, explicit;

  key = idsa_mex_get(m);
  type = idsa_mex_get(m);
  if ((key == NULL) || (type == NULL)) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  implicit = idsa_resolve_type(IDSA_M_UNKNOWN, key->t_buf);
  explicit = idsa_type_code(type->t_buf);

  if (explicit == IDSA_T_NULL) {
    idsa_chain_error_usage(c, "unknown type \"%s\" for \"%s\"", type->t_buf, key->t_buf);
    return -1;
  }
  if ((implicit != IDSA_T_NULL) && (implicit != explicit)) {
    idsa_chain_error_usage(c, "conflicting types for \"%s\"", key->t_buf);
    return -1;
  }

  strncpy(e->t_key, key->t_buf, IDSA_M_NAME);
  e->t_key[IDSA_M_NAME - 1] = '\0';
  e->t_type = explicit;

  return 0;
}

/****************************************************************************/
/* Does       : Create an existance test instance                           */

static void *type_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  TYPE_DATA *e;

  e = malloc(sizeof(TYPE_DATA));
  if (e == NULL) {
    idsa_chain_error_malloc(c, sizeof(TYPE_DATA));
    return NULL;
  }

  if (type_parse(m, c, e)) {
    free(e);
    return NULL;
  }

  return e;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int type_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  TYPE_DATA d, *e, *f;
  int result;

  e = (TYPE_DATA *) t;
  f = &d;

  if (type_parse(m, c, f)) {
    return -1;
  }

  result = strcmp(e->t_key, f->t_key);
  if (result == 0) {
    if (e->t_type != f->t_type) {
      result = (e->t_type > f->t_type) ? 1 : (-1);
    }
  }

  return result;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int type_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  TYPE_DATA *e;
  IDSA_UNIT *unit;

  e = (TYPE_DATA *) t;

  unit = idsa_event_unitbyname(q, e->t_key);
  if (unit == NULL) {
    return 0;
  }

  if (e->t_type == IDSA_T_NULL) {
    return 1;
  }

  if (idsa_unit_type(unit) == e->t_type) {
    return 1;
  }

  return 0;
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void type_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  TYPE_DATA *e;

  e = (TYPE_DATA *) t;

  if (e != NULL) {
    free(e);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_type(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "type", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &type_test_start;
    result->test_cache = &type_test_cache;
    result->test_do = &type_test_do;
    result->test_stop = &type_test_stop;
  }

  return result;
}
