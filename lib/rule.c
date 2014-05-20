#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>

#include <idsa_internal.h>

int idsa_chain_run(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l)
{
  int result;
  IDSA_RULE_NODE *node;
  IDSA_RULE_BODY *body;
  IDSA_RULE_ACTION *action;
  int i;

  result = IDSA_CHAIN_OK;
  node = l->l_node;

#ifdef DEBUG
  fprintf(stderr, "idsa_chain_run(): root=%p\n", node);
#endif

  /* later this loop might have to be split for interleaving of requests */
  while (node) {
#ifdef DEBUG
    fprintf(stderr, "idsa_chain_run(): considering node %p: count=%d\n", node, node->n_count);
#endif
    if (node->n_body) {
      body = node->n_body;
      if (body->b_drop) {
	/* mumble, could be made part of the reply */
	result = IDSA_CHAIN_DROP;
      }
      if (body->b_deny) {
	idsa_reply_deny(l->l_reply);
      }
      for (i = 0; i < body->b_have; i++) {
	action = body->b_array[i];
	idsa_module_do_action(c, action, l->l_request, l->l_reply);
      }
    }
    if (node->n_test) {
      if (idsa_module_do_test(c, node->n_test, l->l_request)) {
	node = node->n_true;
#ifdef DEBUG
	fprintf(stderr, "idsa_chain_run(): taking true branch to %p\n", node);
#endif
      } else {
	node = node->n_false;
#ifdef DEBUG
	fprintf(stderr, "idsa_chain_run(): taking false branch to %p\n", node);
#endif
      }
    } else {
      node = NULL;
    }
  }

  l->l_node = NULL;

  return result;
}

IDSA_RULE_CHAIN *idsa_chain_start(IDSA_EVENT * e, int flags)
{
  IDSA_RULE_CHAIN *result;

  result = idsa_chain_new();
  if (result) {
    result->c_event = e;
    result->c_flags = flags;
    idsa_module_start_global(result);
  } else {
    if (e) {
      idsa_scheme_error_malloc(e, sizeof(IDSA_RULE_CHAIN));
    }
  }

  return result;
}

int idsa_chain_stop(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_TEST *ti, *tj;
  IDSA_RULE_ACTION *ai, *aj;

  if (c) {

    idsa_node_free(c, c->c_nodes);

    /* clear out tests */
    ti = c->c_tests;
    while (ti) {
      tj = ti;
      ti = ti->t_next;
      idsa_module_stop_test(c, tj);
    }
    c->c_tests = NULL;

    /* clear out actions */
    ai = c->c_actions;
    while (ai) {
      aj = ai;
      ai = ai->a_next;
      idsa_module_stop_action(c, aj);
    }
    c->c_actions = NULL;

    /* deallocate all module structures */
    idsa_module_stop_global(c);


#ifdef DEBUG
    if (c->c_modulecount) {
      fprintf(stderr, "idsa_chain_stop(): modulecount=%d\n", c->c_modulecount);
      exit(1);
    }
    if (c->c_nodecount) {
      fprintf(stderr, "idsa_chain_stop(): nodecount=%d\n", c->c_nodecount);
      exit(1);
    }
    if (c->c_testcount) {
      fprintf(stderr, "idsa_chain_stop(): testcount=%d\n", c->c_testcount);
      exit(1);
    }
    if (c->c_actioncount) {
      fprintf(stderr, "idsa_chain_stop(): actioncount=%d\n", c->c_actioncount);
      exit(1);
    }
#endif

    /* deallocate memory */
    idsa_chain_free(c);
  }

  return 0;
}

/****************************************************************************/

IDSA_RULE_CHAIN *idsa_chain_new()
{
  IDSA_RULE_CHAIN *result = NULL;

  result = malloc(sizeof(IDSA_RULE_CHAIN));
  if (result) {
    result->c_nodes = NULL;
    result->c_tests = NULL;
    result->c_actions = NULL;
    result->c_modules = NULL;

    result->c_nodecount = 0;
    result->c_testcount = 0;
    result->c_actioncount = 0;
    result->c_modulecount = 0;
    result->c_rulecount = 0;

    result->c_flags = 0;

    result->c_fresh = 0;
    result->c_error = 0;
    result->c_event = NULL;

    result->c_chain = NULL;
  }

  return result;
}

int idsa_chain_failure(IDSA_RULE_CHAIN * c)
{
  return c->c_error;
}

int idsa_chain_notice(IDSA_RULE_CHAIN * c)
{
  return c->c_fresh;
}

int idsa_chain_reset(IDSA_RULE_CHAIN * c)
{
  c->c_fresh = 0;
  return 0;
}

int idsa_chain_free(IDSA_RULE_CHAIN * c)
{
  if (c) {
    free(c);
  }
  return 0;
}

char *idsa_chain_getname(IDSA_RULE_CHAIN * c)
{
  if (c == NULL) {
    return NULL;
  }

  return c->c_chain;
}

void idsa_chain_setname(IDSA_RULE_CHAIN * c, char *name)
{
  if (c == NULL) {
    return;
  }

  c->c_chain = name;
}

IDSA_RULE_ACTION *idsa_action_new(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_ACTION *result;

  result = malloc(sizeof(IDSA_RULE_ACTION));
  if (result) {
    c->c_actioncount++;
    result->a_module = NULL;
    result->a_next = NULL;
    result->a_state = NULL;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_ACTION));
  }

  return result;
}

int idsa_action_free(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a)
{
  if (a) {
    c->c_actioncount--;
    a->a_next = NULL;
    free(a);
  }
  return 0;
}

IDSA_RULE_BODY *idsa_body_new(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_BODY *result;

  result = malloc(sizeof(IDSA_RULE_BODY));
  if (result) {
    c->c_rulecount++;
    result->b_deny = 0;
    result->b_drop = 0;
    result->b_continue = 0;
    result->b_have = 0;
    result->b_array = NULL;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_BODY));
  }

  return result;
}

IDSA_RULE_BODY *idsa_body_clone(IDSA_RULE_CHAIN * c, IDSA_RULE_BODY * b)
{
  IDSA_RULE_BODY *result;
  int i;

  result = malloc(sizeof(IDSA_RULE_BODY));
  if (result) {
    result->b_have = 0;
    if (b->b_have) {
      result->b_array = malloc(sizeof(IDSA_RULE_ACTION *) * (b->b_have));
      if (result->b_array) {
	result->b_have = b->b_have;
      }
    }

    if (result->b_have == b->b_have) {
      c->c_rulecount++;
      for (i = 0; i < b->b_have; i++) {
	result->b_array[i] = b->b_array[i];
      }
      result->b_deny = b->b_deny;
      result->b_drop = b->b_drop;
      result->b_continue = b->b_continue;
    } else {
      idsa_chain_error_malloc(c, sizeof(IDSA_RULE_ACTION *) * (b->b_have));
      free(result);
      result = NULL;
    }
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_BODY));
  }

  return result;
}

/****************************************************************************/
/* Does       : appends action to rule body                                 */
/* Errors     : c->error set on failure                                     */
/* Notes      : probably unwise to optize out duplicate actions on a path,  */
/*              instead keep explict ordering and have user notice          */

void idsa_body_add(IDSA_RULE_CHAIN * c, IDSA_RULE_BODY * b, IDSA_RULE_ACTION * a)
{
  IDSA_RULE_ACTION **tmp;

  tmp = realloc(b->b_array, sizeof(IDSA_RULE_ACTION *) * (b->b_have + 1));
  if (tmp) {
    b->b_array = tmp;
#ifdef DEBUG
    fprintf(stderr, "idsa_body_add(): insert at position %d\n", b->b_have);
#endif
    b->b_array[b->b_have] = a;
    b->b_have++;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_ACTION *) * (b->b_have + 1));
  }
}

int idsa_body_free(IDSA_RULE_CHAIN * c, IDSA_RULE_BODY * b)
{
  if (b) {
    c->c_rulecount--;
    if (b->b_array) {
      free(b->b_array);
      b->b_array = NULL;
      b->b_have = 0;
    }
    free(b);
  }
  return 0;
}

IDSA_RULE_NODE *idsa_node_new(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_NODE *result;

  result = malloc(sizeof(IDSA_RULE_NODE));
  if (result) {
#ifdef DEBUG
    fprintf(stderr, "idsa_node_new(): new node %p\n", result);
#endif
    c->c_nodecount++;

    result->n_test = NULL;

    result->n_false = NULL;
    result->n_true = NULL;

    result->n_body = NULL;

    result->n_count = 0;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_NODE));
  }

  return result;
}

int idsa_node_free(IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * n)
{
  if (n) {

    if (n->n_count <= 0) {

#ifdef DEBUG
      fprintf(stderr, "idsa_node_free(): deleting node %p\n", n);
#endif

      c->c_nodecount--;

      /* tests take care of themselves */
      n->n_test = NULL;

      if (n->n_true) {
	n->n_true->n_count--;
	idsa_node_free(c, n->n_true);
	n->n_true = NULL;
      }
      if (n->n_false) {
	n->n_false->n_count--;
	idsa_node_free(c, n->n_false);
	n->n_false = NULL;
      }

      idsa_body_free(c, n->n_body);
      n->n_body = NULL;

      free(n);
    } else {
#ifdef DEBUG
      fprintf(stderr, "idsa_node_free(): ignoring node %p, count is %d\n", n, n->n_count);
#endif
    }
  }

  return 0;
}

IDSA_RULE_TEST *idsa_test_new(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_TEST *result;
  result = malloc(sizeof(IDSA_RULE_TEST));

  if (result) {
    c->c_testcount++;
    result->t_next = NULL;
    result->t_module = NULL;
    result->t_state = NULL;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_TEST));
  }

  return result;
}

int idsa_test_free(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t)
{
  if (t) {
    c->c_testcount--;
    t->t_next = NULL;
    /* state gets deallocated elsewhere */
    free(t);
  }
  return 0;
}

IDSA_MODULE *idsa_module_new(IDSA_RULE_CHAIN * c, char *name)
{
  return idsa_module_new_version(c, name, 0);
}

IDSA_MODULE *idsa_module_new_version(IDSA_RULE_CHAIN * c, char *name, int ver)
{
  IDSA_MODULE *result;

  if (ver > IDSA_MODULE_INTERFACE_VERSION) {
    idsa_chain_error_usage(c, "module \"%s\" is requires interface version %d, library only supports %d", name, ver, IDSA_MODULE_INTERFACE_VERSION);
    return NULL;
  }

  result = malloc(sizeof(IDSA_MODULE));
  if (result) {

    c->c_modulecount++;

    result->m_version = ver;

    strncpy(result->m_name, name, IDSA_M_NAME - 1);
    result->m_name[IDSA_M_NAME - 1] = '\0';

    result->m_next = NULL;
    result->m_state = NULL;
    result->m_handle = NULL;

    result->global_start = NULL;
    result->global_before = NULL;
    result->global_after = NULL;
    result->global_stop = NULL;

    result->test_start = NULL;
    result->test_cache = NULL;
    result->test_do = NULL;
    result->test_stop = NULL;

    result->action_start = NULL;
    result->action_cache = NULL;
    result->action_do = NULL;
    result->action_stop = NULL;

  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_MODULE));
  }

  return result;
}

void idsa_module_free(IDSA_RULE_CHAIN * c, IDSA_MODULE * m)
{
  if (m) {
    c->c_modulecount--;
    m->m_next = NULL;
    free(m);
  }
}

IDSA_RULE_LOCAL *idsa_local_new(IDSA_RULE_CHAIN * c)
{
  IDSA_RULE_LOCAL *result;

  result = malloc(sizeof(IDSA_RULE_LOCAL));
  if (result) {
    result->l_result = IDSA_CHAIN_OK;

    result->l_request = NULL;
    result->l_reply = NULL;

    result->l_node = c->c_nodes;
  } else {
    idsa_chain_error_malloc(c, sizeof(IDSA_RULE_LOCAL));
  }
  return result;
}

void idsa_local_free(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l)
{
  if (l) {
    free(l);
  }
}

int idsa_local_init(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l, IDSA_EVENT * q, IDSA_EVENT * p)
{
  l->l_node = c->c_nodes;
  l->l_request = q;
  l->l_reply = p;
  l->l_result = IDSA_CHAIN_OK;

  return 0;
}

int idsa_local_quit(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l)
{

  /* currently do nothing, later if traversals are interleaved unlock nodes */
  l->l_node = c->c_nodes;
  l->l_request = NULL;
  l->l_reply = NULL;

  return 0;
}
