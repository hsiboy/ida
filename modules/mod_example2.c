/* useless example module which triggers on every nth event, where 
 * n can be selected by a user 
 *
 * usage    %example2 3: log file /dev/stdout
 *
 * will log every third event to stdout
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct example2_data {
  int e_count;
  int e_modulo;
};

/****************************************************************************/
/* Does       : Create a test instance                                      */

static void *example2_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  struct example2_data *result;
  IDSA_MEX_TOKEN *token;
  int modulo;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  modulo = atoi(token->t_buf);
  if (modulo == 0) {
    idsa_chain_error_usage(c, "require a nonzero argument for example2 module");
    return NULL;
  }

  result = malloc(sizeof(struct example2_data));
  if (result == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct example2_data));
    return NULL;
  }

  result->e_modulo = modulo;
  result->e_count = 0;

  return result;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int example2_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct example2_data *data;
  IDSA_MEX_TOKEN *token;
  int modulo;

  data = (struct example2_data *) t;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return 1;
  }

  modulo = atoi(token->t_buf);
  if (modulo == 0) {
    idsa_chain_error_usage(c, "require a nonzero argument for example2 module");
    return 1;
  }

  if (modulo > data->e_modulo) {
    return 1;
  }
  if (modulo < data->e_modulo) {
    return -1;
  }

  return 0;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int example2_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct example2_data *result;

  result = (struct example2_data *) t;

  result->e_count++;

  if ((result->e_count) % (result->e_modulo)) {	/* if there is a remainder then don't match */
    return 0;
  } else {			/* every nth event is matched */
    return 1;
  }
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void example2_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct example2_data *result;

  result = (struct example2_data *) t;

  if (result != NULL) {
    free(result);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_example2(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "example2", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &example2_test_start;
    result->test_cache = &example2_test_cache;
    result->test_do = &example2_test_do;
    result->test_stop = &example2_test_stop;
  }

  return result;
}
