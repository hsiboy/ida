/* toy module which always matches, no parameters */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

/****************************************************************************/
/* Does       : Create a test instance, mod_true does not need any state    */

static void *true_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  return NULL;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */
/*              In this example all instances are the same, so we always    */
/*              return equal (0)                                            */

static int true_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  return 0;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Returns    : always 1                                                    */

static int true_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  return 1;
}

/****************************************************************************/
/* Does       : Nothing, no state to deallocate                             */

static void true_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_true(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "true", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &true_test_start;
    result->test_cache = &true_test_cache;
    result->test_do = &true_test_do;
    result->test_stop = &true_test_stop;
  }

  return result;
}
