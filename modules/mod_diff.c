/* a module which triggers if there at least n differences between
   successive events */

/* usage: % diff instance_name number_of_differences */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct diff_data {
  int d_number;
  IDSA_EVENT *d_event;
  char *d_name;
};

static void diff_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t);

static void *diff_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  struct diff_data *result;
  IDSA_MEX_TOKEN *token;
  char *name;
  int number;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }
  name = token->t_buf;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }
  number = atoi(token->t_buf);
  if (number == 0) {
    idsa_chain_error_usage(c, "require a nonzero argument for diff module");
    return NULL;
  }

  result = malloc(sizeof(struct diff_data));
  if (result == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct diff_data));
    return NULL;
  }

  result->d_number = number;
  result->d_event = idsa_event_new(0);
  result->d_name = strdup(name);

  if ((result->d_event == NULL) || (result->d_name == NULL)) {
    idsa_chain_error_malloc(c, result->d_event ? strlen(result->d_name) + 1 : IDSA_M_MESSAGE);
    diff_test_stop(c, NULL, result);
    return NULL;
  }

  return result;
}

static int diff_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct diff_data *data;
  IDSA_MEX_TOKEN *token;
  int number;
  char *name;
  int result;

  data = (struct diff_data *) t;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return 1;
  }
  name = token->t_buf;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return 1;
  }

  number = atoi(token->t_buf);
  if (number == 0) {
    idsa_chain_error_usage(c, "require a nonzero argument for diff module");
    return 1;
  }

  result = strcmp(name, data->d_name);

  if (result == 0) {
    if (number != data->d_number) {
      idsa_chain_error_usage(c, "variable \"%s\" has inconsistent difference counts %d != %d", name, number, data->d_number);
    }
  }

  return result;
}

static int diff_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct diff_data *data;
  IDSA_EVENT *alpha, *beta;
  IDSA_UNIT *ua, *ub;
  int a, b;
  int m, i;
  int count;
  int compare = IDSA_COMPARE_EQUAL;

  data = (struct diff_data *) t;

  alpha = data->d_event;
  beta = q;

  a = idsa_event_unitcount(alpha);
  b = idsa_event_unitcount(beta);

  if (a > b) {
    count = a - b;
    m = b;
  } else {
    count = b - a;
    m = a;
  }

#ifdef TRACE
  fprintf(stderr, "diff_test_do(): initial difference: %d\n", count);
  fprintf(stderr, "diff_test_do(): max=%d", m);
#endif

  for (i = 0; i < m; i++) {
    ua = idsa_event_unitbynumber(alpha, i);
    ub = idsa_event_unitbynumber(beta, i);

#ifdef TRACE
    fprintf(stderr, " [%d]%s[%d]", i, idsa_unit_name_get(ua), count);
#endif

    if (ua && ub) {
      compare = idsa_unit_compare(ua, ub);
      if (compare & IDSA_COMPARE_DISJOINT) {	/* no intersection */
	count++;
	if (count >= data->d_number) {
	  i = m;
	}
      }
    }
  }

#ifdef TRACE
  fprintf(stderr, "\n");
#endif

  idsa_event_copy(alpha, beta);

#ifdef TRACE
  fprintf(stderr, "diff_test_do(): final difference: %d, set: %d\n", count, data->d_number);
#endif

  if (count < data->d_number) {
    return 0;
  } else {
    return 1;
  }
}

static void diff_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct diff_data *result;

  result = (struct diff_data *) t;

  if (result != NULL) {
    if (result->d_event) {
      idsa_event_free(result->d_event);
      result->d_event = NULL;
    }
    if (result->d_name) {
      free(result->d_name);
      result->d_name = NULL;
    }
    free(result);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_diff(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "diff", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &diff_test_start;
    result->test_cache = &diff_test_cache;
    result->test_do = &diff_test_do;
    result->test_stop = &diff_test_stop;
  }

  return result;
}
