#include <stdarg.h>
#include <stdio.h>

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include "scheme.h"

#define BUFFER_SIZE 512

static int scheme_error(IDSA_CONNECTION * c, IDSA_EVENT * e, int f, unsigned ar, unsigned cr, unsigned ir, char *s, va_list ap)
{
  int result = IDSA_L_DENY;
  char buffer[BUFFER_SIZE];

  if (e && c) {
    idsa_risks(e, f, ar, cr, ir);

    if (s) {
      vsnprintf(buffer, BUFFER_SIZE, s, ap);
      buffer[BUFFER_SIZE - 1] = '\0';
      idsa_add_string(e, idsa_resolve_name(IDSA_O_COMMENT), buffer);

      /* wow, so many alternatives */
      /*
         idsa_event_scanappend(e, "comment", IDSA_T_STRING, buffer);
         idsa_event_scanappend(e, idsa_reserved_namebynumber(IDSA_N_COMMENT), IDSA_T_STRING, buffer);
       */
    }
    result = idsa_log(c, e);
  }
  return result;
}

int scheme_error_system(IDSA_CONNECTION * c, int f, unsigned ar, unsigned cr, unsigned ir, int r, char *n, char *s, ...)
{
  int result = IDSA_L_DENY;
  va_list ap;
  IDSA_EVENT *e;

  va_start(ap, s);
  e = idsa_event(c);
  if (e) {
    idsa_name(e, "error-system");

    idsa_add_string(e, IDSA_ES, IDSA_ES_SYSTEM);
    idsa_add_string(e, "module", n);
    idsa_add_set(e, IDSA_ES_SYS_ERRNO, IDSA_T_ERRNO, &r);

    result = scheme_error(c, e, f, ar, cr, ir, s, ap);
  }
  va_end(ap);
  return result;
}

int scheme_error_unhandled(IDSA_CONNECTION * c, int f, unsigned ar, unsigned cr, unsigned ir, char *n, char *s, ...)
{
  int result = IDSA_L_DENY;
  va_list ap;
  IDSA_EVENT *e;

  va_start(ap, s);
  e = idsa_event(c);
  if (e) {
    idsa_name(e, "error-unhandled");

    idsa_add_string(e, IDSA_ES, IDSA_ES_UNHANDLED);
    idsa_add_string(e, "unhandled", n);

    result = scheme_error(c, e, f, ar, cr, ir, s, ap);
  }
  va_end(ap);
  return result;
}

int scheme_error_usage(IDSA_CONNECTION * c, int f, unsigned ar, unsigned cr, unsigned ir, char *s, ...)
{
  int result = IDSA_L_DENY;
  va_list ap;
  IDSA_EVENT *e;

  va_start(ap, s);
  e = idsa_event(c);
  if (e) {
    idsa_name(e, "error-usage");

    idsa_add_string(e, IDSA_ES, IDSA_ES_USAGE);

    result = scheme_error(c, e, f, ar, cr, ir, s, ap);
  }
  va_end(ap);
  return result;
}

int scheme_error_protocol(IDSA_CONNECTION * c, int f, unsigned ar, unsigned cr, unsigned ir, char *s, ...)
{
  int result = IDSA_L_DENY;
  va_list ap;
  IDSA_EVENT *e;

  va_start(ap, s);
  e = idsa_event(c);
  if (e) {
    idsa_name(e, "error-protocol");

    idsa_add_string(e, IDSA_ES, IDSA_ES_PROTOCOL);

    result = scheme_error(c, e, f, ar, cr, ir, s, ap);
  }
  va_end(ap);
  return result;
}
