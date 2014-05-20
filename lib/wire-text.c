/****************************************************************************/
/*                                                                          */
/*  This used to be a fancy protocol, but got lobotomized and is now a      */
/*  single request / reply pair. The format resembles the ones proposed     */
/*  by Matt Bishop and the GULP group, slightly. Possible improvements:     */
/*                                                                          */
/*    variable sized units (ick, need to hack event.c and unit.c)           */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <idsa_internal.h>

/****************************************************************************/
/* Does       : drop event into buffer                                      */
/* Returns    : amount copied on success, negative on failure               */

int idsa_event_tobuffer(IDSA_EVENT * e, char *s, int l)
{
  unsigned int i, m;
  int p, j;
  IDSA_UNIT *u;
  char *name, *type;
  unsigned int nl, tl;

  m = idsa_event_unitcount(e);
  j = 0;
  if (j >= l) {
    return -1;
  }

  switch (e->e_magic) {
  case IDSA_MAGIC_REQUEST:
    s[j] = '?';
    break;
  case IDSA_MAGIC_REPLY:
    s[j] = '!';
    break;
  default:
    return -1;
    break;
  }

  for (i = 0; i < m; i++) {	/* for each triple */
    j++;
    u = idsa_event_unitbynumber(e, i);
    if (u == NULL) {
      return -1;
    }

    name = idsa_unit_name_get(u);
    type = idsa_type_name(idsa_unit_type(u));
    if ((name == NULL) || (type == NULL)) {
      return -1;
    }

    nl = strlen(name);
    tl = strlen(type);
    if (j + nl + tl + 5 >= l) {
      return -1;
    }

    memcpy(s + j, name, nl);
    j += nl;
    s[j++] = ':';
    memcpy(s + j, type, tl);
    j += tl;
    s[j++] = '=';
    s[j++] = '"';

    p = idsa_unit_print(u, s + j, l - j, 1);
    if (p < 0) {
      return -1;
    }
    j += p;

    if (j + 2 >= l) {
      return -1;
    }
    s[j++] = '"';
    s[j] = '\t';
  }
  s[j++] = '\n';

  return j;
}

/****************************************************************************/
/* Does       : copy event from buffer                                      */
/* Returns    : amount copied on success, -1 on failure                     */

int idsa_event_frombuffer(IDSA_EVENT * e, char *s, int l)
{
  unsigned int i, x, t;
  int j;
  char *name, *value, *type;
  char buffer[IDSA_M_MESSAGE];

  if (l <= 0) {
#ifdef DEBUG
    fprintf(stderr, "idsa_event_frombuffer(): buffer too short: %d\n", l);
#endif
    return -1;
  }

  if (l > IDSA_M_MESSAGE) {
    for (i = 0; (i < IDSA_M_MESSAGE) && (s[i] != '\n'); i++);
    if (i >= IDSA_M_MESSAGE) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_frombuffer(): event too long: %d\n", l);
#endif
      return -1;
    }
    l = i + 1;
  }

  memcpy(buffer, s, l);
  j = 0;

  switch (buffer[j]) {
  case '?':
    idsa_event_clear(e, IDSA_MAGIC_REQUEST);
    break;
  case '!':
    idsa_event_clear(e, IDSA_MAGIC_REPLY);
    break;
  default:
#ifdef DEBUG
    fprintf(stderr, "idsa_event_frombuffer(): bad magic\n");
#endif
    return -1;
    break;
  }

  while (j < l) {
    j++;
    name = buffer + j;		/* assume start of name */
    while ((j < l) && (buffer[j] != ':')) {
      j++;
    }
    if (j + 1 >= l) {
      return -1;
    }
    buffer[j++] = '\0';

    type = buffer + j;		/* start of type */
    while ((j < l) && (buffer[j] != '=')) {
      j++;
    }
    if (j + 2 >= l) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_frombuffer(): truncation in type\n");
#endif
      return -1;
    }
    buffer[j++] = '\0';
    j++;

    value = buffer + j;		/* start of value */
    x = 0;
    while ((j < l) && (buffer[j] != '\t') && (buffer[j] != '\n')) {
      x++;
      j++;
    }
    if (j > l) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_frombuffer(): truncation in value\n");
#endif
      return -1;
    }

    if (x) {
      x--;
    }
    x = idsa_descape_unix(value, x);	/* interpret any escapes */
    value[x] = '\0';

    t = idsa_type_code(type);	/* get symbolic code */
    if (t == IDSA_T_NULL) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_frombuffer(): unknown type\n");
#endif
      return -1;
    }
#ifdef DEBUG
    fprintf(stderr, "idsa_event_frombuffer(): got unit <%s:%u:%s>\n", name, t, value);
#endif

    if (idsa_event_scanappend(e, name, t, value) == NULL) {	/* add the unit to event */
#ifdef DEBUG
      fprintf(stderr, "idsa_event_frombuffer(): append failed\n");
#endif
      return -1;
    }

    if (buffer[j] == '\n') {	/* end of event */
      return ++j;
    }
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_event_frombuffer(): dropped out of loop, j=%d, buffer[%d]=<%c>\n", j, j, buffer[j]);
#endif

  return -1;
}

#ifdef STANDALONE

#define MAX 10240
#define COUNT 512
#define BUFFER 128

int main()
{
  char buffer[MAX];
  char check[MAX];
  unsigned int max, result;
  IDSA_EVENT *e, *f;
  int i, j;
  char name[BUFFER];

  e = idsa_event_new(0);
  f = idsa_event_new(0);

  srand(getpid());

  for (i = 0; i < COUNT; i++) {

    memset(buffer, 'X', MAX);
    memset(check, 'X', MAX);

    for (j = 0; j < BUFFER; j++) {
      name[j] = rand() & 0xff;
    }
    name[BUFFER - 1] = '\0';

    idsa_request_init(e, "ee\"ie", "meani\n", name);
    idsa_event_dump(e, stderr);

    max = idsa_event_tobuffer(e, buffer, MAX);
    if (max <= 0) {
      return -1;
    }

    result = idsa_event_frombuffer(f, buffer, max);
    if (result != max) {
      printf("read=%d != write=%d\a\n", result, max);
      exit(1);
    }
    idsa_event_dump(f, stderr);

    idsa_event_tobuffer(f, check, MAX);

    buffer[MAX - 1] = '\0';
    check[MAX - 1] = '\0';

    puts(buffer);

    if (memcmp(buffer, check, MAX)) {
      printf("differences: ouch\a\n");
      puts(check);
      exit(1);
    } else {
      printf("match: ok\n");
    }
  }

  return 0;
}
#endif
