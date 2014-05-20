#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>

#include <idsa_internal.h>

static IDSA_RULE_CHAIN *idsa_parse_chain(IDSA_EVENT * e, IDSA_MEX_STATE * m, int flags);

static int idsa_parse_rule(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);

static int idsa_parse_or(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);
static int idsa_parse_and(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);
static int idsa_parse_term(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);
static int idsa_parse_node(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);

static void idsa_parse_graft(IDSA_RULE_NODE * target, IDSA_RULE_NODE * source);
static void idsa_parse_null(IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false);
static void idsa_parse_replace(IDSA_RULE_NODE * root, IDSA_RULE_NODE * old, IDSA_RULE_NODE * new);

#ifdef DEBUG
static void idsa_parse_dump(IDSA_RULE_NODE * root, FILE * fp, int d);
#endif

/****************************************************************************/

static IDSA_MEX_KEYCHAR idsa_kc_table[] = {
  {':', IDSA_PARSE_COLON},
  {';', IDSA_PARSE_SCOLON},
  {'(', IDSA_PARSE_OPEN},
  {')', IDSA_PARSE_CLOSE},
  {'!', IDSA_PARSE_NOT},
  {'&', IDSA_PARSE_AND},
  {'|', IDSA_PARSE_OR},
  {',', IDSA_PARSE_COMMA},
  {'%', IDSA_PARSE_MOD},
  {'\0', 0}
};

static IDSA_MEX_KEYWORD idsa_kw_table[] = {
  {"allow", IDSA_PARSE_ALLOW},
  {"deny", IDSA_PARSE_DENY},
  {"continue", IDSA_PARSE_CONTINUE},
  {"drop", IDSA_PARSE_DROP},
  {NULL, 0}
};

IDSA_RULE_CHAIN *idsa_parse_fd(IDSA_EVENT * e, int fd, int flags)
{
  IDSA_RULE_CHAIN *result = NULL;
  IDSA_MEX_STATE *m;

  m = idsa_mex_fd(fd);
  if (m) {
    result = idsa_parse_chain(e, m, flags);
    idsa_mex_close(m);
  } else {
    /* FIXME: call idsa_error */
  }

  return result;
}

IDSA_RULE_CHAIN *idsa_parse_file(IDSA_EVENT * e, char *fname, int flags)
{
  IDSA_RULE_CHAIN *result = NULL;
  IDSA_MEX_STATE *m;

  m = idsa_mex_file(fname);
  if (m) {
    result = idsa_parse_chain(e, m, flags);
    idsa_mex_close(m);
  } else {
    /* FIXME: call idsa_error */
  }

  return result;
}

IDSA_RULE_CHAIN *idsa_parse_buffer(IDSA_EVENT * e, char *buffer, int len, int flags)
{
  IDSA_RULE_CHAIN *result = NULL;
  IDSA_MEX_STATE *m;

  m = idsa_mex_buffer(buffer, len);
  if (m) {
    result = idsa_parse_chain(e, m, flags);
    idsa_mex_close(m);
  } else {
    /* FIXME: call idsa_error */
  }

  return result;
}

/****************************************************************************/
/* Does       : The overall parsing, called by parse_{file,fd,buffer}       */
/* Parameters : m - token stream, flags - parse options                     */
/* Returns    : rule chain which can be used to test events                 */
/* Errors     :                                                             */
/* Notes      :                                                             */

static IDSA_RULE_CHAIN *idsa_parse_chain(IDSA_EVENT * e, IDSA_MEX_STATE * m, int flags)
{
  IDSA_RULE_CHAIN *c = NULL;
  IDSA_RULE_NODE *root, *true, *false, *previous;
  IDSA_MEX_TOKEN *token;
  char *failure;
  int run;

  c = idsa_chain_start(e, flags);	/* will write error to e */
  if (c == NULL) {
    return NULL;
  }

  /* load up tokenizer */
  if (idsa_mex_tables(m, idsa_kc_table, idsa_kw_table)) {
    idsa_chain_error_mex(c, m);
    idsa_chain_stop(c);
    return NULL;
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_parse_chain(): loaded tokenizer\n");
#endif

  previous = NULL;
  root = idsa_node_new(c);	/* will write error to c-> */
#ifdef DEBUG
  fprintf(stderr, "idsa_parse_file(): new root node %p\n", root);
#endif
  if (root == NULL) {
    idsa_chain_stop(c);
    return NULL;
  }

  c->c_nodes = root;

  run = 1;
  while (run) {
    true = idsa_node_new(c);
    false = idsa_node_new(c);
    if ((idsa_mex_peek(m) == NULL) || c->c_error || (true == NULL)
	|| (false == NULL)) {
#ifdef DEBUG
      fprintf(stderr, "idsa_parse_chain(): ending parse loop\n");
#endif
      if (true)
	idsa_node_free(c, true);
      if (false)
	idsa_node_free(c, false);
      run = 0;
    } else {
      idsa_parse_rule(m, c, root, true, false);
      if (previous) {
	if (previous->n_body) {
	  if (previous->n_body->b_continue) {
	    idsa_parse_graft(root, previous);
	  }
	} else {
#ifdef DEBUG
	  fprintf(stderr, "idsa_parse_chain(): assertion failure: graft should have a body\n");
	  exit(1);
#endif
	}
      }
      previous = true;
      root = false;
    }
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_parse_chain(): graph after parse\n");
  idsa_parse_dump(c->c_nodes, stderr, 0);
#endif

  /* FIXME: optimize */

  /* check for unused tokens */
  token = idsa_mex_peek(m);
  if (token) {
    idsa_chain_error_internal(c, "parsing aborted prematurely before token <%s> on line %d", token->t_buf, token->t_line);
  }

  /* check for tokenizer failure */
  failure = idsa_mex_error(m);
  if (failure) {
    idsa_chain_error_mex(c, m);
  }

  if (idsa_chain_failure(c)) {
    idsa_chain_stop(c);
    return NULL;
  }

  return c;
}

static int idsa_parse_rule(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  IDSA_MEX_TOKEN *token;
  IDSA_RULE_ACTION *action;
  IDSA_RULE_BODY *body;

  c->c_rulecount++;

#ifdef DEBUG
  fprintf(stderr, "idsa_parse_rule(): starting rule %d, root %p, true %p, false %p\n", c->c_rulecount, root, true, false);
#endif

  idsa_parse_or(m, c, root, true, false);

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return c->c_error;
  }

  if (token->t_id != IDSA_PARSE_COLON) {
    idsa_chain_error_token(c, token);
    return c->c_error;
  }


  body = idsa_body_new(c);
  if (body == NULL) {
    return c->c_error;
  }
  true->n_body = body;

  while (c->c_error == 0) {
    token = idsa_mex_get(m);
    if (token == NULL) {
      idsa_chain_error_mex(c, m);
      return c->c_error;
    }
#ifdef DEBUG
    fprintf(stderr, "idsa_parse_chain(): considering action \"%s ...\"\n", token->t_buf);
#endif
    switch (token->t_id) {
    case IDSA_PARSE_ALLOW:
      /* ignored, allow is default */
      break;
    case IDSA_PARSE_DENY:
      body->b_deny = 1;
      break;
    case IDSA_PARSE_DROP:
      body->b_drop = 1;
      break;
    case IDSA_PARSE_CONTINUE:
      body->b_continue = 1;
      break;
    case IDSA_PARSE_SCOLON:
      idsa_chain_error_token(c, token);
      return c->c_error;
      break;
    case IDSA_PARSE_MOD:
      token = idsa_mex_get(m);
      if (token == NULL) {
	idsa_chain_error_mex(c, m);
	return c->c_error;
      }
      /* WARNING: fall through */
    default:
      action = idsa_module_start_action(m, c, token->t_buf);
      if (action) {
	idsa_body_add(c, body, action);
      }
      break;
    }
    token = idsa_mex_get(m);
    if (token == NULL) {
      return c->c_error;
    } else if (token->t_id != IDSA_PARSE_SCOLON) {
      idsa_mex_unget(m, token);
      return c->c_error;
#ifdef DEBUG
      fprintf(stderr, "idsa_parse_chain(): no further actions\n");
#endif
      /* with a bit of luck just eof, not error */
    }
  }

  return c->c_error;
}

static int idsa_parse_or(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  IDSA_RULE_NODE *node;
  IDSA_MEX_TOKEN *token;

  node = idsa_node_new(c);
  if (node == NULL) {
    /* failure, abort but wire up children so they don't get lost */
    idsa_parse_null(root, true, false);
    return c->c_error;
  }

  idsa_parse_and(m, c, root, true, node);
  if (c->c_error) {
    idsa_parse_null(node, true, false);
    return c->c_error;
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_parse_null(node, true, false);
    idsa_chain_error_mex(c, m);
    return c->c_error;
  }

  if (token->t_id != IDSA_PARSE_OR) {
    idsa_parse_replace(root, node, false);
#ifdef DEBUG
    if (node->n_count) {
      fprintf(stderr, "idsa_parse_or(): assertion failure, replacement incomplete\n");
      exit(1);
    }
#endif
    idsa_node_free(c, node);
    idsa_mex_unget(m, token);
    return c->c_error;
  }

  idsa_parse_or(m, c, node, true, false);
  return c->c_error;
}

static int idsa_parse_and(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  IDSA_RULE_NODE *node;
  IDSA_MEX_TOKEN *token;

  node = idsa_node_new(c);
  if (node == NULL) {
    /* failure, abort but wire up children so they don't get lost */
    idsa_parse_null(root, true, false);
    return c->c_error;
  }

  idsa_parse_term(m, c, root, node, false);
  if (c->c_error) {
    idsa_parse_null(node, true, false);
    return c->c_error;
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_parse_null(node, true, false);
    idsa_chain_error_mex(c, m);
    return c->c_error;
  }

  if (token->t_id != IDSA_PARSE_AND) {
    idsa_parse_replace(root, node, true);
#ifdef DEBUG
    if (node->n_count) {
      fprintf(stderr, "idsa_parse_and(): assertion failure, replacement incomplete\n");
      exit(1);
    }
#endif
    idsa_node_free(c, node);
    idsa_mex_unget(m, token);
    return c->c_error;
  }

  idsa_parse_and(m, c, node, true, false);
  return c->c_error;
}

static int idsa_parse_term(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  IDSA_MEX_TOKEN *token;

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_parse_null(root, true, false);
    idsa_chain_error_mex(c, m);
    return c->c_error;
  }

  switch (token->t_id) {
  case IDSA_PARSE_AND:
  case IDSA_PARSE_OR:
  case IDSA_PARSE_COLON:
  case IDSA_PARSE_CLOSE:
    idsa_parse_null(root, true, false);
    idsa_chain_error_token(c, token);
    break;
  case IDSA_PARSE_OPEN:
    idsa_parse_or(m, c, root, true, false);

    token = idsa_mex_get(m);
    if (token) {
      if (token->t_id != IDSA_PARSE_CLOSE) {
	idsa_chain_error_token(c, token);
      }
    } else {
      idsa_chain_error_mex(c, m);
    }
    break;
  case IDSA_PARSE_NOT:
    /* invert */
    idsa_parse_term(m, c, root, false, true);
    break;
  default:
    idsa_mex_unget(m, token);
    idsa_parse_node(m, c, root, true, false);
    break;
  }

  return c->c_error;
}

static int idsa_parse_node(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  IDSA_MEX_TOKEN *token;
  char *module;

  /* wire up root to point to true and false */
  idsa_parse_null(root, true, false);

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return c->c_error;
  }

  if (token->t_id == IDSA_PARSE_MOD) {
    token = idsa_mex_get(m);
    if (token == NULL) {
      idsa_chain_error_mex(c, m);
      return c->c_error;
    } else {
      module = token->t_buf;
    }
  } else {
    idsa_mex_unget(m, token);
    module = "default";
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_parse_node(): module is <%s>\n", module);
#endif

  root->n_test = idsa_module_start_test(m, c, module);

  return c->c_error;
}

static void idsa_parse_graft(IDSA_RULE_NODE * target, IDSA_RULE_NODE * source)
{
  if (target->n_true) {
    source->n_true = target->n_true;
    source->n_true->n_count++;
  }
  if (target->n_false) {
    source->n_false = target->n_false;
    source->n_false->n_count++;
  }
  source->n_test = target->n_test;

  /* FIXME what about any actions in root ? */

}

static void idsa_parse_null(IDSA_RULE_NODE * root, IDSA_RULE_NODE * true, IDSA_RULE_NODE * false)
{
  root->n_true = true;
  root->n_false = false;
  true->n_count++;
  false->n_count++;
}

static void idsa_parse_replace(IDSA_RULE_NODE * root, IDSA_RULE_NODE * old, IDSA_RULE_NODE * new)
{
  if (root->n_true) {
    if (root->n_true == old) {
      root->n_true = new;
      new->n_count++;
      old->n_count--;
    } else {
      idsa_parse_replace(root->n_true, old, new);
    }
  }
  if (root->n_false) {
    if (root->n_false == old) {
      root->n_false = new;
      new->n_count++;
      old->n_count--;
    } else {
      idsa_parse_replace(root->n_false, old, new);
    }
  }
}

/****************************************************************************/

#ifdef DEBUG

/****************************************************************************/
/* Does       : Generates a graphplace graph of the rule graph              */

static void idsa_parse_dump(IDSA_RULE_NODE * root, FILE * fp, int d)
{
  int i, j;

  IDSA_RULE_TEST *t;
  IDSA_RULE_BODY *b;

  t = root->n_test;
  b = root->n_body;

  fprintf(fp, "(");
  if (t) {
    fprintf(fp, "%%%s:", t->t_module->m_name);
  }
  if (b) {
    if (t) {
      fprintf(fp, " ");
    }
    fprintf(fp, "%s", b->b_deny ? "deny" : "allow");

    if (b->b_continue) {
      fprintf(fp, "; continue");
    }

    if (b->b_drop) {
      fprintf(fp, "; drop");
    }

    for (j = 0; j < b->b_have; j++) {
      fprintf(fp, "; %s", b->b_array[j]->a_module->m_name);
    }
  }
  fprintf(fp, ") ");
  fprintf(fp, "%p node\n", root);

  fputc('%', fp);
  for (i = 0; i < d; i++)
    fputc(' ', fp);
  fprintf(fp, " count=%d\n", root->n_count);

  if (b) {

    fputc('%', fp);
    for (i = 0; i < d; i++)
      fputc(' ', fp);
    fprintf(fp, " deny=%d, drop=%d, continue=%d", b->b_deny, b->b_drop, b->b_continue);
    for (j = 0; j < b->b_have; j++) {
      fprintf(fp, " module=%s", b->b_array[j]->a_module->m_name);
    }
    fprintf(fp, "\n");

  }
  if (t) {
    fputc('%', fp);
    for (i = 0; i < d; i++)
      fputc(' ', fp);
    fprintf(fp, " test=%p, module=%s, true=%p, false=%p\n", t, t->t_module->m_name, root->n_true, root->n_false);
  }
  if (root->n_true) {
    fprintf(fp, "(true) () %p %p edge\n", root, root->n_true);
    idsa_parse_dump(root->n_true, fp, d + 2);
  }
  if (root->n_false) {
    fprintf(fp, "(false) () %p %p edge\n", root, root->n_false);
    idsa_parse_dump(root->n_false, fp, d + 2);
  }
}
#endif
