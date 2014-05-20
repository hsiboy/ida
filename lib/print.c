#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>

#include <idsa_internal.h>

/****************************************************************************/

#define IDSA_PI_STRING  0x00	/* plain string */

#define IDSA_PI_GOTO    0x01	/* %{<} */
#define IDSA_PI_LABEL   0x02	/* %{[N]>} start at current or Nth position  */

#define IDSA_PI_CACHE   0x03	/* %{digit|reserved} */
#define IDSA_PI_NAME    0x04	/* %{unresolvable} */
#define IDSA_PI_COUNT   0x05	/* %{nothing} */

#define IDSA_PI_STAMP   0x06	/* %{#} */
#define IDSA_PI_VERSION 0x07	/* %{@} */

struct idsa_print_item {
  int pi_type;

  int pi_index;			/* cached name index */
  IDSA_FUNCTION_PRINT pi_function;	/* function to write unit component */
  int pi_mode;			/* output mode number */
  char *pi_string;		/* spacer string or name field */
  struct idsa_print_item *pi_jump;	/* for jumps */

  struct idsa_print_item *pi_next;
  struct idsa_print_item *pi_prev;
};
typedef struct idsa_print_item IDSA_PRINT_ITEM;

typedef int (*IDSA_PRINT_EVENT) (IDSA_EVENT * e, IDSA_PRINT_HANDLE * p, char *b, int l);

struct idsa_print_handle {
  IDSA_PRINT_EVENT ph_function;
  IDSA_PRINT_ITEM *ph_items;
};
/* typedef struct idsa_print_handle IDSA_PRINT_HANDLE; */

/****************************************************************************/

static int idsa_print_parse_field(IDSA_PRINT_ITEM * p, char *s);
static int idsa_print_parse_item(IDSA_PRINT_ITEM * p, char *s);
static int idsa_print_parse_string(IDSA_PRINT_ITEM * p, char *s);

static int idsa_print_do_internal(IDSA_EVENT * e, IDSA_PRINT_HANDLE * p, char *b, int l);
static int idsa_print_do_template(IDSA_EVENT * e, IDSA_PRINT_HANDLE * p, char *b, int l);

static void idsa_print_item_free(IDSA_PRINT_ITEM * pi);
static IDSA_PRINT_ITEM *idsa_print_item_new(IDSA_PRINT_ITEM * prev);

static int idsa_print_type(IDSA_UNIT * u, char *s, int l, int m);
static int idsa_print_name(IDSA_UNIT * u, char *s, int l, int m);

static int idsa_print_special_stamp(IDSA_UNIT * u, char *s, int l, int m);
static int idsa_print_special_version(IDSA_UNIT * u, char *s, int l, int m);

/****************************************************************************/

struct idsa_print_lookup {
  char *pl_key;
  char *pl_value;
};

static struct idsa_print_lookup idsa_print_table[] = {
  {"csv", "\"%{:1}\"%{1>},\"%{:1}\"%{<}\n"},
  {"ulm", "%{*}=\"%{:1}\"%{1>} %{*}=\"%{:1}\"%{<}\n"},
  {"tulm", "%{*}:%{+}=\"%{:1}\"%{1>} %{*}:%{+}=\"%{:1}\"%{<}\n"},
  {"syslog", "%{time:100} %{host:1} %{service:1}[%{pid}]: %{scheme:1}.%{name:1}%{12>} %{:1}%{<}\n"}, {"native", "%{time:102} %{host:1} %{uid}:%{gid} %{honour} %{arisk}:%{crisk}:%{irisk} %{service:1}:%{pid} %{scheme:1}:%{name:1}%{12>} %{*}=\"%{:1}\"%{<}\n"},
  {"xml", "<event>%{>}<%{*} type=\"%{+}\">%{:2}</%{*}>%{<}</event>\n"},
  {NULL, NULL}
};

IDSA_PRINT_HANDLE *idsa_print_format(char *n)
{
  IDSA_PRINT_HANDLE *ph;
  int i;

  if (!strcmp(n, "internal")) {	/* special case */
    ph = malloc(sizeof(IDSA_PRINT_HANDLE));
    if (ph == NULL) {
      return NULL;
    }
    ph->ph_function = &idsa_print_do_internal;
    ph->ph_items = NULL;
    return ph;
  }

  for (i = 0; (idsa_print_table[i].pl_key != NULL) && (strcmp(idsa_print_table[i].pl_key, n)); i++);
  if (idsa_print_table[i].pl_key != NULL) {
    return idsa_print_parse(idsa_print_table[i].pl_value);
  }

  return NULL;
}

IDSA_PRINT_HANDLE *idsa_print_parse(char *s)
{
  IDSA_PRINT_HANDLE *ph;
  IDSA_PRINT_ITEM *pi;
  int i;

  /* FIXME: maybe an error event parameter to provide details in case of fail */

  ph = malloc(sizeof(IDSA_PRINT_HANDLE));
  if (ph == NULL) {
    return NULL;
  }

  ph->ph_function = &idsa_print_do_template;
  ph->ph_items = NULL;

  if (s[0] != '\0') {
    pi = idsa_print_item_new(NULL);
    ph->ph_items = pi;
  } else {
    pi = NULL;
  }

  while (pi) {
    i = idsa_print_parse_item(pi, s);
    if (i <= 0) {
      i = 0;
      pi = NULL;
    } else {
      s = s + i;
      if (s[0] == '\0') {
	pi = NULL;
      } else {
	pi = idsa_print_item_new(pi);
      }
    }
  }

  if (s[0] != '\0') {		/* incomplete parse indication of error */
    idsa_print_free(ph);
    ph = NULL;
  }

  return ph;
}

int idsa_print_do(IDSA_EVENT * e, IDSA_PRINT_HANDLE * ph, char *b, int l)
{
  return (*ph->ph_function) (e, ph, b, l);
}

void idsa_print_free(IDSA_PRINT_HANDLE * ph)
{
  IDSA_PRINT_ITEM *pi, *pj;

  if (ph) {
    pi = ph->ph_items;
    while (pi) {
      pj = pi;
      pi = pi->pi_next;
      idsa_print_item_free(pj);
    }
    ph->ph_items = NULL;
    free(ph);
  }
}

/****************************************************************************/

static IDSA_PRINT_ITEM *idsa_print_item_new(IDSA_PRINT_ITEM * prev)
{
  IDSA_PRINT_ITEM *pi;
  pi = malloc(sizeof(IDSA_PRINT_ITEM));

  if (pi == NULL) {
    return NULL;
  }

  pi->pi_prev = prev;
  if (prev) {
    prev->pi_next = pi;
  }

  pi->pi_type = 0;
  pi->pi_index = 0;
  pi->pi_mode = 0;

  pi->pi_function = NULL;
  pi->pi_string = NULL;

  pi->pi_jump = NULL;
  pi->pi_next = NULL;

  return pi;
}

static void idsa_print_item_free(IDSA_PRINT_ITEM * pi)
{
#ifdef DEBUG
  fprintf(stderr, "idsa_print_item_free(): deleting item <%p>\n", pi);
#endif
  if (pi) {
    if (pi->pi_string) {
      free(pi->pi_string);
      pi->pi_string = NULL;
    }
    pi->pi_prev = NULL;
    pi->pi_next = NULL;
    pi->pi_jump = NULL;
    free(pi);
  }
}

/****************************************************************************/

static int idsa_print_do_template(IDSA_EVENT * e, IDSA_PRINT_HANDLE * p, char *b, int l)
{
  IDSA_PRINT_ITEM *pi;
  IDSA_UNIT *u;
  int result;
  int count;
  int i;

  result = 0;
  count = 0;
  pi = p->ph_items;

  while (pi) {
    switch (pi->pi_type) {
    case IDSA_PI_STRING:
      for (i = 0; (pi->pi_string[i] != '\0') && (l > result); i++, result++) {
	b[result] = pi->pi_string[i];
      }
      if (pi->pi_string[i] != '\0') {
	return -1;
      }
      break;
    case IDSA_PI_GOTO:
      count++;
      if ((count < idsa_event_unitcount(e)) && (count <= pi->pi_index)) {
	pi = pi->pi_jump;
      }
      break;
    case IDSA_PI_LABEL:
      count = pi->pi_index;
      if (count >= idsa_event_unitcount(e)) {	/* skip loop if index too large */
	pi = pi->pi_jump;
      }
      break;
    case IDSA_PI_CACHE:
      u = idsa_event_unitbynumber(e, pi->pi_index);
      if (u) {
	i = (*pi->pi_function) (u, b + result, l - result, pi->pi_mode);
	if (i > 0) {
	  result += i;
	} else {
	  return -1;
	}
      } else {
	return -1;
      }
      break;
    case IDSA_PI_NAME:
      u = idsa_event_unitbyname(e, pi->pi_string);
      if (u) {
	i = (*pi->pi_function) (u, b + result, l - result, pi->pi_mode);
	if (i > 0) {
	  result += i;
	} else {
	  return -1;
	}
/*
      } else {
	return -1;
*/
      }
      break;
    case IDSA_PI_COUNT:
      u = idsa_event_unitbynumber(e, count);
      if (u) {
	i = (*pi->pi_function) (u, b + result, l - result, pi->pi_mode);
	if (i > 0) {
	  result += i;
	} else {
	  return -1;
	}
      } else {
	return -1;
      }
      break;
    case IDSA_PI_STAMP:
    case IDSA_PI_VERSION:
      i = (*pi->pi_function) (NULL, b + result, l - result, pi->pi_mode);
      if (i > 0) {
	result += i;
      } else {
	return -1;
      }
      break;
    }
    pi = pi->pi_next;
  }

  return result;
}

static int idsa_print_do_internal(IDSA_EVENT * e, IDSA_PRINT_HANDLE * p, char *b, int l)
{
  return idsa_event_tobuffer(e, b, l);
}

static int idsa_print_parse_item(IDSA_PRINT_ITEM * p, char *s)
{
  int result;

#ifdef DEBUG
  fprintf(stderr, "idsa_print_parse_item(): considering <%s>\n", s);
#endif

  switch (s[0]) {
  case '%':
    switch (s[1]) {
    case '{':
      return idsa_print_parse_field(p, s);
    case '%':
      result = idsa_print_parse_string(p, s + 1);
      if (result > 0) {
	result++;
      }
      return result;
    default:
      return idsa_print_parse_string(p, s);
    }
  case '\0':
    return -1;
  default:
    return idsa_print_parse_string(p, s);
  }

  return -1;
}

static int idsa_print_parse_field(IDSA_PRINT_ITEM * p, char *s)
{
  IDSA_PRINT_ITEM *g;
  int i;

#ifdef DEBUG
  fprintf(stderr, "idsa_print_parse_field(): looking at <%s>\n", s);
#endif

  for (i = 2; (s[i] != '\0') && (isalnum(s[i]) || (s[i] == '-') || (s[i] == '_') || (s[i] == '.')); i++);

#ifdef DEBUG
  fprintf(stderr, "idsa_print_parse_field(): skipped to <%c>\n", s[i]);
#endif

  switch (s[i]) {
  case '*':			/* name (deref) */
  case '+':			/* type (liket) */
  case ':':			/* value (common) */
  case '}':			/* value */
    switch (s[i]) {
    case '*':
      p->pi_function = &idsa_print_name;
      break;
    case '+':
      p->pi_function = &idsa_print_type;
      break;
    case ':':
    case '}':
      p->pi_function = &idsa_unit_print;
      break;
    }

    if ((s[i] != '}') && isdigit(s[i + 1])) {
      p->pi_mode = atoi(s + i + 1);
    } else {
      p->pi_mode = 0;
    }

    if (i == 2) {
      p->pi_index = 0;
      p->pi_type = IDSA_PI_COUNT;
    } else {
      p->pi_string = malloc(i - 1);
      if (p->pi_string == NULL) {
	return -1;
      }
      memcpy(p->pi_string, s + 2, i - 2);
      p->pi_string[i - 2] = '\0';

#ifdef DEBUG
      fprintf(stderr, "idsa_print_parse_field(): name <%s>\n", p->pi_string);
#endif

      p->pi_index = idsa_resolve_request(idsa_resolve_code(p->pi_string));
      if (p->pi_index < idsa_request_count()) {
	p->pi_type = IDSA_PI_CACHE;
      } else {
	p->pi_type = IDSA_PI_NAME;
      }
    }
    break;

  case '>':			/* jump target */
    p->pi_type = IDSA_PI_LABEL;
    if (isdigit(s[2])) {
      p->pi_index = atoi(s + 2);
    } else {
      p->pi_index = 0;
    }
    break;
  case '<':			/* jump to previous location */
    p->pi_type = IDSA_PI_GOTO;
    if (isdigit(s[2])) {
      p->pi_index = atoi(s + 2);
    } else {
      p->pi_index = INT_MAX;
    }

    for (g = p->pi_prev; g && (g->pi_type != IDSA_PI_LABEL); g = g->pi_prev);
    if (g) {
      p->pi_jump = g;
      g->pi_jump = p;
    } else {
      return -1;
    }
    break;

  case '#':
    p->pi_type = IDSA_PI_STAMP;
    p->pi_function = &idsa_print_special_stamp;

    p->pi_index = 0;
    p->pi_string = NULL;
    break;
  case '@':
    p->pi_type = IDSA_PI_VERSION;
    p->pi_function = &idsa_print_special_version;

    p->pi_index = 0;
    p->pi_string = NULL;
    break;

  default:
    return -1;
  }

  /* skip to end */
  while ((s[i] != '\0') && (s[i] != '}')) {
    i++;
  }

  if (s[i] == '}') {
    return i + 1;
  } else {
    return -1;
  }

  return -1;
}

static int idsa_print_parse_string(IDSA_PRINT_ITEM * p, char *s)
{
  int i;

  p->pi_type = IDSA_PI_STRING;
  /* WARNING: s[i] can not be '\0' */
  for (i = 1; (s[i] != '\0') && (s[i] != '%'); i++);

  p->pi_string = malloc(i + 1);
  if (p->pi_string) {
    memcpy(p->pi_string, s, i);
    p->pi_string[i] = '\0';
#ifdef DEBUG
    fprintf(stderr, "idsa_print_parse_string(): copied string <%s>\n", p->pi_string);
#endif
    return i;
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_print_parse_string(): copy failed\n");
#endif
    return -1;
  }
}

/****************************************************************************/

static int idsa_print_name(IDSA_UNIT * u, char *s, int l, int m)
{
  char *name;
  int i;

  name = idsa_unit_name_get(u);

  i = strlen(name);
  if (l < i) {
    memcpy(s, name, l);		/* feeble best effort */
    return -1;
  } else {
    memcpy(s, name, i);
    return i;
  }
}

static int idsa_print_type(IDSA_UNIT * u, char *s, int l, int m)
{
  char *type;
  int i;

  type = idsa_type_name(idsa_unit_type(u));

  i = strlen(type);
  if (l < i) {
    memcpy(s, type, l);		/* feeble best effort */
    return -1;
  } else {
    memcpy(s, type, i);
    return i;
  }
}

static int idsa_print_special_stamp(IDSA_UNIT * u, char *s, int l, int m)
{
  static unsigned long stamp = 0;
  int x;

  /* WARNING: some safety issues, duplicate timestamps could happen */
  x = snprintf(s, l, "%lu", stamp++);

  return (l < x) ? (-1) : x;
}

static int idsa_print_special_version(IDSA_UNIT * u, char *s, int l, int m)
{
  int x;

  x = strlen(VERSION);
  if (l < x) {
    memcpy(s, VERSION, l);	/* feeble best effort */
    return -1;
  } else {
    memcpy(s, VERSION, x);
    return x;
  }
}
