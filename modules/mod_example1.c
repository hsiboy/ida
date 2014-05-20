/* useless example module which triggers on every 7th event */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct example1_data {
  int e_count;
};

/****************************************************************************/
/* Does       : Create a test instance                                      */

static void *example1_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  struct example1_data *result;

  result = malloc(sizeof(struct example1_data));
  if (result == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct example1_data));
    return NULL;
  }

  result->e_count = 0;

  return result;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */
/*              In this example all instances are the same, so we always    */
/*              return equal (0)                                            */

static int example1_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  return 0;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int example1_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct example1_data *result;

  result = (struct example1_data *) t;

  result->e_count++;

  if ((result->e_count) % 7) {	/* if there is a remainder/7 then don't match */
    return 0;
  } else {			/* every 7th event is matched */
    return 1;
  }
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void example1_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct example1_data *result;

  result = (struct example1_data *) t;

  if (result != NULL) {
    free(result);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_example1(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "example1", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &example1_test_start;
    result->test_cache = &example1_test_cache;
    result->test_do = &example1_test_do;
    result->test_stop = &example1_test_stop;
  }

  return result;
}
