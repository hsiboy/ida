/* usage: %regex name regular_expression */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>		/* Yuck. Some *BSDs need that for the regex.h */
#include <regex.h>

#include <idsa_internal.h>

struct regex_test_state {
  regex_t r_compiled;
  char *r_regex;
  char *r_name;
  int r_number;
};

static void regex_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t);

static void *regex_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  IDSA_MEX_TOKEN *name, *regex;
  struct regex_test_state *state;

  /* parse test */
  name = idsa_mex_get(m);
  if (!name) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  regex = idsa_mex_get(m);
  if (!regex) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  state = malloc(sizeof(struct regex_test_state));
  if (!state) {
    idsa_chain_error_malloc(c, sizeof(struct regex_test_state));
    return NULL;
  }
  state->r_name = NULL;
  state->r_regex = NULL;

  if (regcomp(&(state->r_compiled), regex->t_buf, REG_EXTENDED | REG_ICASE | REG_NOSUB)) {
    idsa_chain_error_usage(c, "compilation of regular expression on line %d failed", regex->t_line);
    free(state);
    return NULL;
  }

  state->r_name = strdup(name->t_buf);
  if (state->r_name == NULL) {
    idsa_chain_error_malloc(c, strlen(name->t_buf) + 1);
    regex_test_stop(c, NULL, state);
    return NULL;
  }

  state->r_regex = strdup(regex->t_buf);
  if (state->r_regex == NULL) {
    idsa_chain_error_malloc(c, strlen(regex->t_buf) + 1);
    regex_test_stop(c, NULL, state);
    return NULL;
  }

  state->r_number = idsa_resolve_request(idsa_resolve_code(name->t_buf));

  return state;
}

static int regex_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct regex_test_state *cache;
  IDSA_MEX_TOKEN *name, *regex;
  int result;

  cache = (struct regex_test_state *) (t);

  name = idsa_mex_get(m);
  if (!name) {
    idsa_chain_error_mex(c, m);
    return 1;
  }

  regex = idsa_mex_get(m);
  if (!regex) {
    idsa_chain_error_mex(c, m);
    return 1;
  }

  result = strcmp(name->t_buf, cache->r_name);
  if (result != 0) {
    return result;
  }

  result = strcmp(regex->t_buf, cache->r_regex);

  return result;
}

/****************************************************************************/
/* Does       : performs the test on a given event                          */
/* Parameters : c - chain, g - global state, t - per test state, q - request*/
/* Returns    : nonzero if match, zero otherwise                            */
/* Notes      : g and t can be NULL on a per module basis                   */

static int regex_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct regex_test_state *state;
  char buffer[IDSA_M_MESSAGE];
  IDSA_UNIT *unit;
  int len;

  state = (struct regex_test_state *) (t);

  if (state->r_number < idsa_request_count()) {
    unit = idsa_event_unitbynumber(q, state->r_number);
  } else {
    unit = idsa_event_unitbyname(q, state->r_name);
  }

  if (unit == NULL) {
    return 0;
  }

  len = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
  if (len <= 0) {
    return 0;
  }

  buffer[len] = '\0';
  buffer[IDSA_M_MESSAGE - 1] = '\0';

  if (regexec(&(state->r_compiled), buffer, 0, NULL, 0)) {
    return 0;
  }

  return 1;
}

static void regex_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct regex_test_state *state;

  if (t) {
    state = (struct regex_test_state *) (t);

    if (state->r_name) {
      free(state->r_name);
      state->r_name = NULL;
    }
    if (state->r_regex) {
      free(state->r_regex);
      state->r_regex = NULL;
    }

    regfree(&(state->r_compiled));

    free(state);
  }
}

/****************************************************************************/

IDSA_MODULE *idsa_module_load_regex(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "regex", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &regex_test_start;
    result->test_cache = &regex_test_cache;
    result->test_do = &regex_test_do;
    result->test_stop = &regex_test_stop;
  }

  return result;
}
