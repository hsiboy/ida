#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <idsa_internal.h>

struct default_test_state {
  IDSA_UNIT *t_unit;
  int t_number;
  int t_op;
};

/****************************************************************************/

static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type);
static int find_op(IDSA_RULE_CHAIN * c, char *op);

void idsa_default_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t);

/****************************************************************************/

void *idsa_default_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  IDSA_MEX_TOKEN *name, *type, *value, *op;
  unsigned int t;
  IDSA_UNIT *unit;
  struct default_test_state *state;

  /* parse test */
  name = idsa_mex_get(m);
  if (!name) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_default_test_start(): attempting to parse \"%s ...\"\n", name->t_buf);
#endif

  value = idsa_mex_get(m);
  if (!value) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  if (value->t_id == IDSA_PARSE_COLON) {	/* has the user specified a type ? */
    type = idsa_mex_get(m);
    value = idsa_mex_get(m);
    if (!(value && type)) {
      idsa_chain_error_mex(c, m);
      return NULL;
    }
  } else {
    type = NULL;
  }

  if (!idsa_support_eot(c, m)) {	/* is there more to go ? */
    op = value;
    value = idsa_mex_get(m);
    if (!value) {
      idsa_chain_error_mex(c, m);
      return NULL;
    }
  } else {
    op = NULL;
  }

  /* figure out the type */
  t = find_type(c, name->t_buf, type ? type->t_buf : NULL);
  if (t == IDSA_T_NULL) {
    return NULL;
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_default_test_start(): creating unit from %s:%s\n", name->t_buf, value->t_buf);
#endif

  /* build unit */
  unit = idsa_unit_new(name->t_buf, t, value->t_buf);
  if (!unit) {
    idsa_chain_error_internal(c, "unable to create <%s>", value->t_buf);
    return NULL;
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_default_test_start(): created unit: name %s\n", idsa_unit_name_get(unit));
#endif


  state = malloc(sizeof(struct default_test_state));
  if (!state) {
    idsa_chain_error_malloc(c, sizeof(struct default_test_state));
    idsa_unit_free(unit);
    return NULL;
  }

  state->t_unit = unit;
  state->t_number = idsa_resolve_request(idsa_resolve_code(name->t_buf));
  state->t_op = find_op(c, op ? op->t_buf : NULL);

#ifdef DEBUG
  fprintf(stderr, "idsa_default_test_start(): parsed \"%s %s\"\n", name->t_buf, value->t_buf);
#endif

  return state;
}

int idsa_default_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct default_test_state *cache, *state;
  int result = -1;
  int compare;

  cache = (struct default_test_state *) (t);
  state = (struct default_test_state *) (idsa_default_test_start(m, c, g));

  if (!state) {
    return result;
  }

  if (cache->t_op == state->t_op) {
    result = strcmp(idsa_unit_name_get(cache->t_unit), idsa_unit_name_get(state->t_unit));
    if (result == 0) {
      compare = idsa_unit_compare(cache->t_unit, state->t_unit);
      if (compare & IDSA_COMPARE_MORE) {
	result = 1;
      } else if (compare & IDSA_COMPARE_LESS) {
	result = (-1);
      } else {
	result = 0;
      }
    }
  } else {
    result = (cache->t_op > state->t_op) ? 1 : (-1);
  }

  idsa_default_test_stop(c, g, state);

  return result;
}

/****************************************************************************/
/* Does       : performs the test on a given event                          */
/* Parameters : c - chain, g - global state, t - per test state, q - request*/
/* Returns    : nonzero if match, zero otherwise                            */
/* Notes      : g and t can be NULL on a per module basis                   */

int idsa_default_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct default_test_state *state;
  IDSA_UNIT *unit;
  int result = 0;
#ifdef DEBUG
  char buffer[IDSA_M_MESSAGE];
  int len;
#endif

  state = (struct default_test_state *) (t);

  if (state->t_number < idsa_request_count()) {
#ifdef DEBUG
    fprintf(stderr, "idsa_default_test_do(): getting by number %d\n", state->t_number);
#endif
    unit = idsa_event_unitbynumber(q, state->t_number);
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_default_test_do(): getting by name %s\n", idsa_unit_name_get(state->t_unit));
#endif
    unit = idsa_event_unitbyname(q, idsa_unit_name_get(state->t_unit));
  }

  if (unit) {
    if (state->t_op & idsa_unit_compare(unit, state->t_unit)) {
      result = 1;
    }
#ifdef DEBUG
    len = idsa_unit_print(unit, buffer, IDSA_M_MESSAGE - 1, 0);
    buffer[len] = '\0';
    fprintf(stderr, "default_tdo(): comparison of <%s> to <", buffer);
    len = idsa_unit_print(state->t_unit, buffer, IDSA_M_MESSAGE - 1, 0);
    buffer[len] = '\0';
    fprintf(stderr, "%s> yields %d\n", buffer, result);
#endif
  } else {
#ifdef DEBUG
    len = idsa_unit_print(state->t_unit, buffer, IDSA_M_MESSAGE - 1, 0);
    buffer[len] = '\0';
    fprintf(stderr, "default_tdo(): warning: nothing to compare against <%s>\n", buffer);
    idsa_event_dump(q, stderr);
#endif
  }

  return result;
}

void idsa_default_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct default_test_state *state;
  if (t) {
    state = (struct default_test_state *) (t);
    idsa_unit_free(state->t_unit);
    free(state);
  }
}

/****************************************************************************/

IDSA_MODULE *idsa_module_load_default(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "default", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &idsa_default_test_start;
    result->test_cache = &idsa_default_test_cache;
    result->test_do = &idsa_default_test_do;
    result->test_stop = &idsa_default_test_stop;
  }

  return result;
}

/****************************************************************************/

static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type)
{
  unsigned int implicit, explicit;

  implicit = idsa_resolve_type(IDSA_M_UNKNOWN, name);

  if (type == NULL) {		/* easy case, no competitor */
    if (implicit == IDSA_T_NULL) {
      idsa_chain_error_usage(c, "no type given for \"%s\"", name);
    }
    return implicit;
  }

  explicit = idsa_type_code(type);
  if (explicit == IDSA_T_NULL) {	/* failure of explicit lookup is fatal */
    idsa_chain_error_usage(c, "type \"%s\" for \"%s:%s\" does not exist", type, name, type);
    return implicit;
  }

  /* now explicit always has a non-null value */

  if (implicit == IDSA_T_NULL) {	/* nothing implicit */
    return explicit;
  }

  if (implicit != explicit) {	/* two non-null yet different */
    idsa_chain_error_usage(c, "conflicting types for \"%s:%s\"", name, type);
    return IDSA_T_NULL;
  }

  return explicit;
}

static int find_op(IDSA_RULE_CHAIN * c, char *op)
{
  if (op == NULL) {
    return IDSA_COMPARE_INTERSECT;
  }

  if (op[1] != '\0') {
    idsa_chain_error_usage(c, "unknown comparison operator \"%s\"", op);
    return IDSA_COMPARE_EQUAL;
  }

  switch (op[0]) {
  case '>':
    return IDSA_COMPARE_MORE;
  case '<':
    return IDSA_COMPARE_LESS;
  case '^':
    return IDSA_COMPARE_INTERSECT;
  case '=':
    return IDSA_COMPARE_EQUAL;
    break;
  }

  return IDSA_COMPARE_EQUAL;
}
