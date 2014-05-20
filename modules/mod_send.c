/* WARNING: Note that if you send things into the application, you are still
   bounded by unit sizes, eg strings can not be longer than 128. In such
   a case autofile may be used instead of autorule
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sched.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <idsa_internal.h>

/****************************************************************************/

static unsigned int find_type(IDSA_RULE_CHAIN * c, char *name, char *type);

/****************************************************************************/

static void *send_action_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  IDSA_UNIT *result;
  IDSA_MEX_TOKEN *name, *type, *value;
  unsigned int t;

  name = idsa_mex_get(m);
  value = idsa_mex_get(m);
  if (name == NULL || value == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  if (value->t_id == IDSA_PARSE_COLON) {
    type = idsa_mex_get(m);
    value = idsa_mex_get(m);
    if (type == NULL || value == NULL) {
      idsa_chain_error_mex(c, m);
      return NULL;
    }
  } else {
    type = NULL;
  }

  t = find_type(c, name->t_buf, type ? type->t_buf : NULL);
  if (t == IDSA_T_NULL) {
    return NULL;
  }

  result = idsa_unit_new(name->t_buf, t, value->t_buf);
  if (result == NULL) {
    idsa_chain_error_internal(c, "unable to convert \"%s:%s %s\" to a unit", name->t_buf, idsa_type_name(t), value->t_buf);
  }

  return result;
}

static int send_action_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a)
{
  IDSA_UNIT *alpha, *beta;
  int result;
  int compare;

  alpha = a;
  beta = send_action_start(m, c, g);
  if (beta == NULL) {
    return 1;
  }

  result = strcmp(idsa_unit_name_get(alpha), idsa_unit_name_get(beta));
  if (result == 0) {
    compare = idsa_unit_compare(alpha, beta);
    if (compare & IDSA_COMPARE_LESS) {
      result = (-1);
    } else if (compare & IDSA_COMPARE_MORE) {
      result = 1;
    } else {
      result = 0;
    }
  }

  idsa_unit_free(beta);
  return result;
}

static int send_action_do(IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  IDSA_UNIT *unit;
  unit = a;
  if (unit) {
    idsa_event_unitappend(p, unit);
  }
  return 0;
}

static void send_action_stop(IDSA_RULE_CHAIN * c, void *g, void *a)
{
  IDSA_UNIT *unit;
  unit = a;
  if (unit) {
    idsa_unit_free(unit);
  }
}

/****************************************************************************/

IDSA_MODULE *idsa_module_load_send(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "send", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->action_start = &send_action_start;
    result->action_cache = &send_action_cache;
    result->action_do = &send_action_do;
    result->action_stop = &send_action_stop;
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
