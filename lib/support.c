/* support for modules */

#include <idsa_internal.h>

int idsa_support_eot(IDSA_RULE_CHAIN * c, IDSA_MEX_STATE * m)
{
  IDSA_MEX_TOKEN *t;

  t = idsa_mex_peek(m);
  if (t == NULL) {
    idsa_chain_error_mex(c, m);
    return 1;
  }

  switch (t->t_id) {
  case IDSA_PARSE_COLON:
  case IDSA_PARSE_CLOSE:
  case IDSA_PARSE_AND:
  case IDSA_PARSE_OR:
    return 1;
    /* break; */
  }

  return 0;
}
