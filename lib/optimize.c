#include <idsa_internal.h>

struct idsa_node_set {
  int n_have;
  int n_used;
  IDSA_RULE_NODE **n_array;
};
typedef struct idsa_node_set IDSA_NODE_SET;

#define DEFAULT_SET_SIZE 128

static IDSA_NODE_SET *idsa_new_set(IDSA_RULE_CHAIN * c)
{
  IDSA_NODE_SET *result;

  result = malloc(sizeof(IDSA_NODE_SET));
  if (result) {

    result->n_array = malloc(DEFAULT_SET_SIZE * sizeof(IDSA_RULE_NODE *));
    if (result->n_array) {
      result->n_used = 0;
      result->n_have = DEFAULT_SET_SIZE;
    } else {
      free(result);
      result = NULL;
    }
  }

  if (!result) {
    idsa_chain_error_malloc(c, sizeof(IDSA_NODE_SET) + DEFAULT_SET_SIZE * sizeof(IDSA_RULE_NODE *));
  }

  return result;
}

static void idsa_free_set(IDSA_RULE_CHAIN * c, IDSA_NODE_SET * n)
{
  if (n) {
    if (n->n_array) {
      free(n->n_array);
      n->n_array = NULL;
    }
    free(n);
  }
}

static void idsa_push_set(IDSA_RULE_CHAIN * c, IDSA_NODE_SET * n, IDSA_RULE_NODE * a)
{
  IDSA_RULE_NODE **t;

  if (n->n_used >= n->n_have) {
    t = realloc(n->n_array, sizeof(IDSA_RULE_NODE) * 2 * n->n_have);
    if (t) {
      n->n_array = t;
      n->n_have = 2 * n->n_have;
    } else {
      idsa_chain_error_malloc(c, 2 * n->n_have * sizeof(IDSA_RULE_NODE *));
    }
  }

  if (n->n_used < n->n_have) {
    n->n_array[n->n_used] = a;
    n->n_used = n->n_used + 1;
  }
}

static void idsa_del_set(IDSA_RULE_CHAIN * c, IDSA_NODE_SET * n, IDSA_RULE_NODE * d)
{
  int i;
  for (i = 0; i < n->n_used; i++) {
    if (n->n_array[i] == d) {
      n->n_used = n->n_used - 1;
      if (n->n_used > i) {
	n->n_array[i] = n->n_array[n->n_used];
      }
    }
  }
}

static void idsa_clear_set(IDSA_RULE_CHAIN * c, IDSA_NODE_SET * n)
{
  n->n_used = 0;
}

static IDSA_RULE_NODE *idsa_pop_set(IDSA_RULE_CHAIN * c, IDSA_NODE_SET * n)
{
  if (n->n_used > 0) {
    n->n_used = n->n_used - 1;
    return n->n_array[n->n_used];
  } else {
    return NULL;
  }
}
