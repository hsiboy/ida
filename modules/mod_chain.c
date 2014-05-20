/* Tests what chain is currently being evaluated.
 * Currently four chains exist: server, auto, pre and fail
 * Probably only useful in pre and fail chain
 *
 * usage    %chain pre: deny; log file /dev/stdout
 *
 * will print every event to stdout in client, but contact server
 * too. This rule needs to be sent to the client using %send
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct chain_data {
  char d_name[IDSA_M_NAME];
};

/****************************************************************************/
/* Does       : Create a test instance                                      */

static int chain_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, struct chain_data *d)
{
  IDSA_MEX_TOKEN *token;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  strncpy(d->d_name, token->t_buf, IDSA_M_NAME - 1);
  d->d_name[IDSA_M_NAME - 1] = '\0';

  return 0;
}

static void *chain_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  struct chain_data *d;

  d = malloc(sizeof(struct chain_data));
  if (d == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct chain_data));
    return NULL;
  }

  if (chain_parse(m, c, d)) {
    free(d);
    return NULL;
  }

  return d;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int chain_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct chain_data *d, *e, f;
  int result;

  d = (struct chain_data *) t;
  e = &f;

  if (chain_parse(m, c, e)) {
    return 1;
  }

  result = strncmp(d->d_name, e->d_name, IDSA_M_NAME - 1);

  if (result > 1) {
    result = 1;
  } else if (result < (-1)) {
    result = -1;
  }

  return result;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int chain_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct chain_data *d;
  int result;
  char *name;

  d = (struct chain_data *) t;
  name = idsa_chain_getname(c);

  if (name == NULL) {
    return 0;
  }

  result = strncmp(name, d->d_name, IDSA_M_NAME - 1);

  if (result) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void chain_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct chain_data *d;

  d = (struct chain_data *) t;

  if (d != NULL) {
    free(d);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_chain(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "chain", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &chain_test_start;
    result->test_cache = &chain_test_cache;
    result->test_do = &chain_test_do;
    result->test_stop = &chain_test_stop;
  }

  return result;
}
