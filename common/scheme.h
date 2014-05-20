#ifndef _IDSA_SCHEME_H_
#define _IDSA_SCHEME_H_

#include <stdarg.h>
#include <idsa.h>

int scheme_error_system   (IDSA_CONNECTION *c, int f, unsigned ar, unsigned cr, unsigned ir, int r, char *n, char *s, ...);
int scheme_error_unhandled(IDSA_CONNECTION *c, int f, unsigned ar, unsigned cr, unsigned ir, char *n, char *s, ...);
int scheme_error_usage    (IDSA_CONNECTION *c, int f, unsigned ar, unsigned cr, unsigned ir, char *s, ...);
int scheme_error_protocol (IDSA_CONNECTION *c, int f, unsigned ar, unsigned cr, unsigned ir, char *s, ...);

#endif
