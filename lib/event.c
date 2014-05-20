

/****************************************************************************/
/*                                                                          */
/*  Manipulate the event structure. Somebody had suggested that I should    */
/*  make sure performance was ok, so my structure is the same as the wire   */
/*  protocol - 4k structure, 5 integer header with sequence of units as     */
/*  body and small index at tail. In retrospect it might be better to       */
/*  have a bit of a performance hit and do a decent structure and human     */
/*  readable (or at least platform independent) protocol. Could be doable   */
/*  using idsa_unit_scan and idsa_unit_print. Another thing to add to the   */
/*  TODO list, sigh.                                                        */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <idsa_internal.h>

#define idsa_event_space(e) (IDSA_M_MESSAGE-(e->e_size+(e->e_count*sizeof(int))))

/****************************************************************************/
/* Does       : Formats event with required fields                          */

void idsa_event_clear(IDSA_EVENT * e, unsigned int m)
{
  e->e_magic = m;
  e->e_size = IDSA_S_OFFSET;
  e->e_count = 0;

  /* pointless, but tidy */
  memset(e->e_ptr, '\0', IDSA_M_UNITS);

#ifdef DEBUG
  fprintf(stderr, "idsa_event_clear(): formatted event\n");
#endif

}

/****************************************************************************/
/* Does       : allocate event structure                                    */

IDSA_EVENT *idsa_event_new(unsigned int m)
{
  IDSA_EVENT *e;

  e = malloc(sizeof(IDSA_EVENT));
  if (e) {
    idsa_event_clear(e, m);
  }
  return e;
}

/****************************************************************************/
/* Does       : Deallocate event resources                                  */

void idsa_event_free(IDSA_EVENT * e)
{
  free(e);
}

/****************************************************************************/
/* Does       : Make copy of event                                          */

void idsa_event_copy(IDSA_EVENT * a, IDSA_EVENT * b)
{
  a->e_magic = b->e_magic;
  a->e_size = b->e_size;
  a->e_count = b->e_count;
  memcpy(a->e_ptr, b->e_ptr, IDSA_M_UNITS);
}

/****************************************************************************/
/* Does       : appends one event to another, used to record idsad reply    */
/*              along with event reported by application                    */

int idsa_event_concat(IDSA_EVENT * t, IDSA_EVENT * s)
{
  int result = 0;
  unsigned int i;
  IDSA_UNIT *u;

  for (i = 0; i < s->e_count; i++) {
    u = idsa_event_unitbynumber(s, i);
    if (u) {
      if (idsa_event_unitappend(t, u) == NULL) {
	result++;
      }
    } else {
      result++;
    }
  }

  return result;
}


/****************************************************************************/
/* Does       : Eyeballs event, attempts to overwrite as much as possible   */
/*              to make it consistent, and build index                      */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_event_check(IDSA_EVENT * e)
{
  int result = 0;
  unsigned int offset, lookup, i, len;
  IDSA_UNIT *u;

  i = 0;
  offset = 0;
  lookup = IDSA_M_UNITS;

  while (i < e->e_count) {
    u = (IDSA_UNIT *) (e->e_ptr + offset);
    lookup -= (sizeof(unsigned int));

    if (offset + sizeof(IDSA_UNIT) - IDSA_M_LONG > lookup) {	/* not even enough to read type */
#ifdef DEBUG
      fprintf(stderr, "idsa_event_check(): failure at %d: %d+%d>%d\n", i + 1, offset, sizeof(IDSA_UNIT) - IDSA_M_LONG, lookup);
#endif
      result++;
      e->e_count = i;
    } else {			/* sufficent to read name and type */
      len = idsa_unit_size(u);

      if ((offset + len > lookup) || idsa_unit_check(u)) {	/* unit too long or buggered */
#ifdef DEBUG
	fprintf(stderr, "idsa_event_check(): failure at [%d] <%s> 0x%04x: %d+%d>%d\n", i + 1, idsa_unit_name_get(u), idsa_unit_type(u), offset, len, lookup);
#endif
	result++;
	e->e_count = i;
      } else {
#ifdef DEBUG
	fprintf(stderr, "idsa_event_check(): [%d] <%s> 0x%04x: ok\n", i + 1, idsa_unit_name_get(u), idsa_unit_type(u));
#endif
	memcpy(e->e_ptr + lookup, &offset, sizeof(int));	/* add index */
	i++;
	offset += len;
      }
    }
  }
  e->e_size = IDSA_S_OFFSET + offset;

#ifdef DEBUG
  idsa_event_dump(e, stderr);
#endif

  return result;
}

/****************************************************************************/
/* Does       : Writes event in format friendly to bug chasers              */

int idsa_event_dump(IDSA_EVENT * e, FILE * f)
{
  IDSA_UNIT *u;
  unsigned int l, i, j;
  int r;
  unsigned int offset, lookup;
  char buffer[IDSA_M_MESSAGE];

  l = e->e_size - IDSA_S_OFFSET;
  i = 0;
  j = 0;

  fprintf(f, "event: magic <0x%04x>, size <%d>\n", e->e_magic, e->e_size);
  fprintf(f, "event: ptr <%p>, ptrsize <%d>, count <%d>\n", e->e_ptr, l, e->e_count);

  while (i < l) {
    u = (IDSA_UNIT *) (e->e_ptr + i);
    lookup = IDSA_M_UNITS - (sizeof(unsigned int) * (j + 1));
    memcpy(&offset, e->e_ptr + lookup, sizeof(unsigned int));
    r = idsa_unit_print(u, buffer, IDSA_M_MESSAGE - 1, 0);
    if (r < 0) {
      r = 0;
    }
    buffer[r] = '\0';

    fprintf(f, "unit[%02d]: %p[%04d [%04d]=%04d]: 0x%04x, <%s>, <%s:%d>\n", j + 1, e->e_ptr, i, lookup, offset, idsa_unit_type(u), idsa_unit_name_get(u), buffer, r);

    i += idsa_unit_size(u);
    j++;
  }

  return 0;
}

/* modify existing and new units ******************************************* */

/****************************************************************************/
/* Does       : looks up unit by index and sets its value to pointer p      */

IDSA_UNIT *idsa_event_setbynumber(IDSA_EVENT * e, int n, void *p)
{
  IDSA_UNIT *u;
  u = idsa_event_unitbynumber(e, n);
  if (u && p) {
    if (idsa_unit_set(u, p)) {
      u = NULL;
    }
  }
  return u;
}

/****************************************************************************/
/* Does       : looks up unit by index and parses its value from string s   */

IDSA_UNIT *idsa_event_scanbynumber(IDSA_EVENT * e, int n, char *s)
{
  IDSA_UNIT *u;
  u = idsa_event_unitbynumber(e, n);
  if (u && s) {
    if (idsa_unit_scan(u, s)) {
      u = NULL;
    }
  }
  return u;
}

/****************************************************************************/
/* Does       : appends new unit to event with value set to pointer p       */

IDSA_UNIT *idsa_event_setappend(IDSA_EVENT * e, char *n, unsigned int t, void *p)
{
  IDSA_UNIT *u;
  u = idsa_event_append(e, t);
#ifdef DEBUG
  fprintf(stderr, "idsa_event_setappend(): appended unit at <%p>\n", u);
#endif
  if (u) {
    if (n) {
      idsa_unit_name_set(u, n);
    }
    if (p) {
      if (idsa_unit_set(u, p)) {
	u = NULL;
      }
    }
  }
  return u;
}

/****************************************************************************/
/* Does       : appends new unit to event with value scanned from string s  */

IDSA_UNIT *idsa_event_scanappend(IDSA_EVENT * e, char *n, unsigned int t, char *s)
{
  IDSA_UNIT *u;
  u = idsa_event_append(e, t);
  if (u) {
    if (n) {
      idsa_unit_name_set(u, n);
    }
    if (s) {
      if (idsa_unit_scan(u, s)) {
	u = NULL;
      }
    }
  }
  return u;
}

/****************************************************************************/
/* Does       : appends new unit to event with no value                     */

IDSA_UNIT *idsa_event_unitappend(IDSA_EVENT * e, IDSA_UNIT * u)
{
  IDSA_UNIT *v;
  v = idsa_event_append(e, u->u_type);
  if (v) {
    idsa_unit_copy(v, u);
  }
  return v;
}

/* return units, either existing or new appended *************************** */

/****************************************************************************/
/* Does       : retrieves number of elements in a given event               */

unsigned int idsa_event_unitcount(IDSA_EVENT * e)
{
  return e->e_count;
}

/****************************************************************************/
/* Does       : looks up a unit by name starting at last one                */
/* Returns    : pointer to unit on success, NULL otherwise                  */

IDSA_UNIT *idsa_event_unitbyname(IDSA_EVENT * e, char *n)
{
  IDSA_UNIT *result;
  unsigned int i, offset;

  i = e->e_count;

  while (i > 0) {
    memcpy(&offset, e->e_ptr + (IDSA_M_UNITS - (sizeof(unsigned int) * i)), sizeof(unsigned int));
    result = (IDSA_UNIT *) (e->e_ptr + offset);
    if (strncmp(idsa_unit_name_get(result), n, IDSA_M_NAME)) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_unitbyname(): skipping [%d]=%p (%s)\n", i, result, idsa_unit_name_get(result));
#endif
    } else {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_unitbyname(): got it [%d]=%p (%s)\n", i, result, idsa_unit_name_get(result));
#endif
      return result;
    }
    i--;
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_event_unitbyname(): could not find (%s)\n", n);
#endif

  return NULL;
}

/****************************************************************************/
/* Does       : looks up a unit by index                                    */
/* Returns    : pointer to unit on success, NULL otherwise                  */

IDSA_UNIT *idsa_event_unitbynumber(IDSA_EVENT * e, int n)
{
  IDSA_UNIT *result;
  unsigned int offset;

  if (n < e->e_count) {
    memcpy(&offset, e->e_ptr + (IDSA_M_UNITS - (sizeof(unsigned int) * (n + 1))), sizeof(unsigned int));
    result = (IDSA_UNIT *) (e->e_ptr + offset);
#ifdef DEBUG
    fprintf(stderr, "idsa_event_unitbynumber(): got it [%d]=%p (%s)\n", n, result, idsa_unit_name_get(result));
#endif
    return result;
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_event_unitbynumber(): not found [%d] is too large\n", n);
#endif
    return NULL;
  }
}

/****************************************************************************/
/* Does       : Add another unit to event                                   */
/* Returns    : pointer to unit on success, NULL otherwise                  */

IDSA_UNIT *idsa_event_append(IDSA_EVENT * e, unsigned int t)
{
  unsigned int have, want, offset;
  IDSA_UNIT *result;


#ifdef DEBUG
  fprintf(stderr, "idsa_event_append(): appending unit type=<%d>\n", t);
#endif

  have = idsa_event_space(e);
  want = sizeof(unsigned int) + sizeof(IDSA_UNIT) + idsa_type_size(t) - IDSA_M_LONG;

  if (have < want) {
#ifdef DEBUG
    fprintf(stderr, "idsa_event_append(): not enough space\n");
#endif
    return NULL;
  }

  if ((t >= IDSA_M_TYPES) || (t == IDSA_T_NULL)) {
    return NULL;
  }

  offset = e->e_size - IDSA_S_OFFSET;
  result = (IDSA_UNIT *) (e->e_ptr + offset);
  e->e_count++;
  memcpy(e->e_ptr + (IDSA_M_UNITS - (sizeof(unsigned int) * e->e_count)), &offset, sizeof(unsigned int));	/* build index */

#ifdef DEBUG
  fprintf(stderr, "idsa_event_append(): %d: %p[%d], [%d]=%u\n", e->e_count, e->e_ptr, offset, (IDSA_M_UNITS - (sizeof(unsigned int) * e->e_count)), offset);
#endif

  idsa_unit_name_set(result, "");

  result->u_type = t;
  e->e_size += idsa_unit_size(result);

  return result;
}
