#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>

#include <idsa_internal.h>
#include <idsa_schemes.h>

/****************************************************************************/
/* parse errors, to export for other modules ********************************/

void idsa_chain_error_system(IDSA_RULE_CHAIN * c, int e, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  if ((c->c_event != NULL) && (c->c_fresh == 0)) {
    idsa_scheme_verror_system(c->c_event, e, s, ap);
  }

  c->c_fresh = 1;
  c->c_error = 1;

  va_end(ap);
}

void idsa_chain_error_internal(IDSA_RULE_CHAIN * c, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  if ((c->c_event != NULL) && (c->c_fresh == 0)) {
    idsa_scheme_verror_internal(c->c_event, s, ap);
  }

  c->c_fresh = 1;
  c->c_error = 1;

  va_end(ap);
}

void idsa_chain_error_usage(IDSA_RULE_CHAIN * c, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  if ((c->c_event != NULL) && (c->c_fresh == 0)) {
    idsa_scheme_verror_usage(c->c_event, s, ap);
  }

  c->c_fresh = 1;
  c->c_error = 1;

  va_end(ap);
}

void idsa_chain_error_malloc(IDSA_RULE_CHAIN * c, int bytes)
{
  if ((c->c_event != NULL) && (c->c_fresh == 0)) {
    idsa_scheme_error_malloc(c->c_event, bytes);
  }

  c->c_fresh = 1;
  c->c_error = 1;
}

/****************************************************************************/

/****************************************************************************/
/* Notes      : no reliance on scheme, since unlikely to occur outside chain*/

void idsa_chain_error_token(IDSA_RULE_CHAIN * c, IDSA_MEX_TOKEN * t)
{
  char buffer[IDSA_M_STRING];

  if ((c->c_event != NULL) && (c->c_fresh == 0)) {

    snprintf(buffer, IDSA_M_STRING - 1, "unexpected token <%s> on line %d", t->t_buf, t->t_line);
    buffer[IDSA_M_STRING - 1] = '\0';

    idsa_request_scan(c->c_event, "parse-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, buffer, NULL);

  }

  c->c_fresh = 1;
  c->c_error = 1;

}

/****************************************************************************/
/* Notes      : no reliance on scheme, since unlikely to occur outside chain*/

void idsa_chain_error_mex(IDSA_RULE_CHAIN * c, IDSA_MEX_STATE * m)
{
  char *ptr;

  ptr = idsa_mex_error(m);

  if ((c->c_event != NULL) && (c->c_fresh == 0)) {

    idsa_request_scan(c->c_event, "tokenizing-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, ptr ? ptr : "unexpected end of rule chain", NULL);

  }

  c->c_fresh = 1;
  c->c_error = 1;

}

/****************************************************************************/

void idsa_scheme_error_system(IDSA_EVENT * evt, int err, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  idsa_scheme_verror_system(evt, err, s, ap);

  va_end(ap);
}

void idsa_scheme_verror_system(IDSA_EVENT * evt, int err, char *s, va_list ap)
{
  char buffer[IDSA_M_STRING];

  vsnprintf(buffer, IDSA_M_STRING - 1, s, ap);
  buffer[IDSA_M_STRING - 1] = '\0';

  idsa_request_scan(evt, "system-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, NULL);

  idsa_event_setappend(evt, IDSA_ES_SYS_ERRNO, IDSA_T_ERRNO, &err);
  idsa_event_scanappend(evt, "comment", IDSA_T_STRING, buffer);
}

void idsa_scheme_error_internal(IDSA_EVENT * evt, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  idsa_scheme_verror_internal(evt, s, ap);

  va_end(ap);
}

void idsa_scheme_verror_internal(IDSA_EVENT * evt, char *s, va_list ap)
{
  char buffer[IDSA_M_STRING];

  vsnprintf(buffer, IDSA_M_STRING - 1, s, ap);
  buffer[IDSA_M_STRING - 1] = '\0';

  idsa_request_scan(evt, "internal-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_INTERNAL, "comment", IDSA_T_STRING, buffer, NULL);
}

void idsa_scheme_error_usage(IDSA_EVENT * evt, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  idsa_scheme_verror_usage(evt, s, ap);

  va_end(ap);
}

void idsa_scheme_verror_usage(IDSA_EVENT * evt, char *s, va_list ap)
{
  char buffer[IDSA_M_STRING];

  vsnprintf(buffer, IDSA_M_STRING - 1, s, ap);
  buffer[IDSA_M_STRING - 1] = '\0';

  idsa_request_scan(evt, "usage-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, buffer, NULL);
}

void idsa_scheme_error_malloc(IDSA_EVENT * evt, int bytes)
{
  char buffer[IDSA_M_STRING];

  snprintf(buffer, IDSA_M_STRING - 1, "unable to allocate %d bytes", bytes);
  buffer[IDSA_M_STRING - 1] = '\0';

  idsa_request_scan(evt, "memory-error", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, NULL);

  idsa_event_setappend(evt, "bytes", IDSA_T_INT, &bytes);
  idsa_event_scanappend(evt, "comment", IDSA_T_STRING, buffer);
}
