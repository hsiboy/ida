/* existence test. Will test if an event contains a field with given name
 *
 * usage    %exists name
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

typedef struct exists_data {
  char e_key[IDSA_M_NAME];
} EXISTS;

static int exists_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, EXISTS * e)
{
  IDSA_MEX_TOKEN *key;

  key = idsa_mex_get(m);
  if (key == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  strncpy(e->e_key, key->t_buf, IDSA_M_NAME);
  e->e_key[IDSA_M_NAME - 1] = '\0';

  return 0;
}

/****************************************************************************/
/* Does       : Create an existance test instance                           */

static void *exists_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  EXISTS *e;

  e = malloc(sizeof(EXISTS));
  if (e == NULL) {
    idsa_chain_error_malloc(c, sizeof(EXISTS));
    return NULL;
  }

  if (exists_parse(m, c, e)) {
    free(e);
    return NULL;
  }

  return e;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int exists_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  EXISTS d, *e, *f;
  int result;

  e = (EXISTS *) t;
  f = &d;

  if (exists_parse(m, c, f)) {
    return -1;
  }

  result = strcmp(e->e_key, f->e_key);

  return result;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int exists_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  EXISTS *e;
  IDSA_UNIT *unit;

  e = (EXISTS *) t;

  unit = idsa_event_unitbyname(q, e->e_key);
  if (unit == NULL) {
    return 0;
  }

  return 1;
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void exists_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  EXISTS *e;

  e = (EXISTS *) t;

  if (e != NULL) {
    free(e);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_exists(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "exists", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &exists_test_start;
    result->test_cache = &exists_test_cache;
    result->test_do = &exists_test_do;
    result->test_stop = &exists_test_stop;
  }

  return result;
}
