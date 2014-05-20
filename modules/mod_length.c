/* length test. Will test if a value, converted to a string exeeds a given length
 *
 * usage    %length label [:type] [operation] integer
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <idsa_internal.h>

#define OP_EQ  0
#define OP_GT  1
#define OP_LT  2

static char *length_ops[] = {
  [OP_EQ] = "=",
  [OP_GT] = ">",
  [OP_LT] = "<",
  NULL
};

typedef struct length_data {
  char l_label[IDSA_M_NAME];
  unsigned l_length;
  unsigned l_op;
} LENGTH_DATA;

static int length_parse(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, LENGTH_DATA * e)
{
  IDSA_MEX_TOKEN *label, *length;
  unsigned int i;

  label = idsa_mex_get(m);
  length = idsa_mex_get(m);
  if ((label == NULL) || (length == NULL)) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  strncpy(e->l_label, label->t_buf, IDSA_M_NAME - 1);
  e->l_label[IDSA_M_NAME - 1] = '\0';

  if (length->t_id == IDSA_PARSE_COLON) {
    idsa_mex_get(m);
    length = idsa_mex_get(m);
    if (length == NULL) {
      idsa_chain_error_mex(c, m);
      return -1;
    }
  }

  e->l_op = OP_EQ;

  for (i = 0; length_ops[i]; i++) {
    if (!strcmp(length_ops[i], length->t_buf)) {
      e->l_op = i;
      length = idsa_mex_get(m);
      if (length == NULL) {
	idsa_chain_error_mex(c, m);
	return -1;
      }
    }
  }

  if (!isdigit(length->t_buf[0])) {
    idsa_chain_error_usage(c, "needed a number to measure length instead of \"%s\"", length->t_buf);
    return -1;
  }

  e->l_length = atoi(length->t_buf);

  return 0;
}

/****************************************************************************/
/* Does       : Create a length test instance                               */

static void *length_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  LENGTH_DATA *e;

  e = malloc(sizeof(LENGTH_DATA));
  if (e == NULL) {
    idsa_chain_error_malloc(c, sizeof(LENGTH_DATA));
    return NULL;
  }

  if (length_parse(m, c, e)) {
    free(e);
    return NULL;
  }

  return e;
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int length_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  LENGTH_DATA d, *e, *f;
  int result;

  e = (LENGTH_DATA *) t;
  f = &d;

  if (length_parse(m, c, f)) {
    return -1;
  }

  result = strcmp(e->l_label, f->l_label);
  if (result) {
    return result;
  }

  if (e->l_length != f->l_length) {
    return (e->l_length > f->l_length) ? 1 : (-1);
  }

  if (e->l_op != f->l_op) {
    return (e->l_op > f->l_op) ? 1 : (-1);
  }

  return 0;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int length_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  char buffer[IDSA_M_LONG];
  LENGTH_DATA *e;
  IDSA_UNIT *unit;
  int x;

  e = (LENGTH_DATA *) t;

  unit = idsa_event_unitbyname(q, e->l_label);
  if (unit == NULL) {
    return 0;
  }

  x = idsa_unit_print(unit, buffer, IDSA_M_LONG - 1, 0);
  if (x < 0) {
    x = IDSA_M_LONG;
  }

  switch (e->l_op) {
  case OP_EQ:
    if (x == e->l_length) {
      return 1;
    }
    break;
  case OP_GT:
    if (x > e->l_length) {
      return 1;
    }
    break;
  case OP_LT:
    if (x < e->l_length) {
      return 1;
    }
    break;
  default:
    /* should not happen */
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": got unknown operation %d\n", e->l_op);
#endif
    break;
  }

  return 0;
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */
/* Parameters : g - global state: always NULL in this module as no gstart() */
/*              and gstop() functions are defined, t - test state: any data */
/*              returned by test_start                                      */

static void length_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  LENGTH_DATA *e;

  e = (LENGTH_DATA *) t;

  if (e != NULL) {
    free(e);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_length(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "length", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &length_test_start;
    result->test_cache = &length_test_cache;
    result->test_do = &length_test_do;
    result->test_stop = &length_test_stop;
  }

  return result;
}
