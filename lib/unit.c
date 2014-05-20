
/****************************************************************************/
/*                                                                          */
/*  Work on individual units (typed label value pairs). Fixed size. Is      */
/*  it worthwhile to make some variable in size ?                           */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <idsa_internal.h>

unsigned int idsa_unit_type(IDSA_UNIT * u)
{
  return u->u_type;
}

char *idsa_unit_name_get(IDSA_UNIT * u)
{
  return u->u_name;
}

int idsa_unit_name_set(IDSA_UNIT * u, char *n)
{
  int i;

  for (i = 0; (i < IDSA_M_NAME - 1) && (n[i] != '\0'); i++) {
    if (isalnum(n[i])) {
      u->u_name[i] = n[i];
    } else {
      switch (n[i]) {
      case '.':
      case '_':
      case '-':
	u->u_name[i] = n[i];
	break;
      default:
	u->u_name[i] = '_';
	break;
      }
    }
  }
  u->u_name[i] = '\0';

  return i;
}

int idsa_unit_size(IDSA_UNIT * u)
{
  return idsa_type_size(u->u_type) + sizeof(IDSA_UNIT) - IDSA_M_LONG;
}

IDSA_UNIT *idsa_unit_new(char *n, unsigned int type, char *s)
{
  IDSA_UNIT *u;
  unsigned int realsize;

  if (idsa_type_lookup(type) == NULL) {
#ifdef DEBUG
    fprintf(stderr, "idsa_unit_new(): type or length too long\n");
#endif
    return NULL;
  }

  realsize = idsa_type_size(type) + sizeof(IDSA_UNIT) - IDSA_M_LONG;

#ifdef DEBUG
  fprintf(stderr, "idsa_unit_new(): allocating %d bytes (instead of full %d)\n", realsize, sizeof(IDSA_UNIT));
#endif

  if (realsize > sizeof(IDSA_UNIT)) {
    return NULL;
  }
  u = malloc(realsize);
  if (u) {
#ifdef DEBUG
    fprintf(stderr, "idsa_unit_new(): copying name %s\n", n);
#endif
    idsa_unit_name_set(u, n);
    u->u_type = type;
    if (s) {
#ifdef DEBUG
      fprintf(stderr, "idsa_unit_new(): copying payload\n");
#endif
      if (idsa_unit_scan(u, s)) {
	free(u);
	u = NULL;
      }
    }
  }
  return u;
}

void idsa_unit_copy(IDSA_UNIT * a, IDSA_UNIT * b)
{
  if (a->u_type == b->u_type) {
#ifdef DEBUG
    fprintf(stderr, "idsa_unit_copy(): copying %d bytes\n", idsa_type_size(a->u_type));
#endif
    strncpy(a->u_name, b->u_name, IDSA_M_NAME);
    memcpy(a->u_ptr, b->u_ptr, idsa_type_size(b->u_type));
  }
}

IDSA_UNIT *idsa_unit_dup(IDSA_UNIT * u)
{
  IDSA_UNIT *result;

  result = malloc(idsa_unit_size(u));
  if (result) {
    strncpy(result->u_name, u->u_name, IDSA_M_NAME);
    result->u_type = u->u_type;
    memcpy(result->u_ptr, u->u_ptr, idsa_type_size(u->u_type));
  }
  return result;
}

void idsa_unit_free(IDSA_UNIT * u)
{
#ifdef DEBUG
  fprintf(stderr, "idsa_unit_free(): deleting unit <%p>\n", u);
#endif
  free(u);
}
