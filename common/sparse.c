#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <sys/types.h>

#include <idsa.h>

#include "sparse.h"

#define DEFAULT_PRI   13	/* 8(user)+5(notice) */

#define LOOK_END   0
#define LOOK_LABEL 1
#define LOOK_VALUE 2

int parse_extra(IDSA_EVENT * evt, char *service, char *message)
{
  char *end;
  char label[IDSA_M_NAME];
  char prefix[IDSA_M_NAME];
  char value[IDSA_M_LONG];
  int state;
  int j, i, ls, le, vs, ve, sc, tc;
  int result;

  state = LOOK_LABEL;
  ls = le = 0;
  vs = ve = 0;
  i = 0;
  result = 0;

  end = "";

  sc = strlen(service);
  if (sc > IDSA_M_NAME / 2) {
    sc = IDSA_M_NAME / 2;
  }
  strncpy(prefix, service, sc);
  prefix[sc] = '.';
  sc++;
  prefix[sc] = '\0';

  while (state != LOOK_END) {
    switch (state) {
    case LOOK_LABEL:
      if (message[i] == '\0') {
	state = LOOK_END;
      } else if (message[i] == '=') {
	if (le > ls) {
	  tc = le - ls;
	  if (message[ls] == '.') {
	    if (tc >= IDSA_M_NAME) {
	      tc = IDSA_M_NAME - 1;
	    }
	    strncpy(label, message + ls, tc);
	    label[tc] = '\0';
	  } else {
	    strncpy(label, prefix, sc);
	    if (tc >= (IDSA_M_NAME - sc)) {
	      tc = IDSA_M_NAME - (sc + 1);
	    }
	    strncpy(label + sc, message + ls, tc);
	    label[tc + sc] = '\0';
	  }

#ifdef TRACE
	  fprintf(stderr, __FUNCTION__ ": got label <%s> starting at %d\n", label, ls);
#endif

	  i++;
	  if (message[i] == '\0') {
	    state = LOOK_END;
	  } else {
	    switch (message[i]) {
	    case '<':
	      i++;
	      end = ">";
	      break;
	    case '(':
	      i++;
	      end = ")";
	      break;
	    case '[':
	      i++;
	      end = "]";
	      break;
	    case '"':
	      i++;
	      end = "\"";
	      break;
	    case '\'':
	      i++;
	      end = "'";
	      break;
	    case '`':
	      i++;
	      end = "`'";
	      break;
	    default:
	      end = " \t";
	      break;
	    }
	    ve = vs = i;
	    state = LOOK_VALUE;
	  }
	} else {
	  i++;
	  ls = le = i;
	}
      } else if (isspace(message[i])) {
	i++;
	ls = le = i;
      } else {
	i++;
	le = i;
      }
      break;
    case LOOK_VALUE:
      for (j = 0; (end[j] != '\0') && (end[j] != message[i]); j++);
      if (end[j] == message[i]) {
	if (ve > vs) {
	  tc = ve - vs;
	  if (tc >= IDSA_M_LONG) {
	    tc = IDSA_M_LONG - 1;
	  }
	  strncpy(value, message + vs, tc);
	  value[tc] = '\0';

	  result += idsa_add_string(evt, label, value);
	}

	if (message[i] == '\0') {
	  state = LOOK_END;
	} else {
	  state = LOOK_LABEL;
	  i++;
	  ls = le = i;
	}
      } else {
	i++;
	ve = i;
      }
      break;
    }
  }

  return result;
}

int parse_event(IDSA_EVENT * evt, char *buf)
{
  int result = 0;

  pid_t pid = 0;
  unsigned int pri = DEFAULT_PRI;
  int j = 0;
  int i = 0;
  int k = 0;
  char *service = NULL;
  char *message = buf;

  if ((evt == NULL) || (buf == NULL)) {	/* unreasonable input */
#ifdef TRACE
    fprintf(stderr, "parse_event(): NULL data\n");
#endif
    return 1;
  }
#ifdef TRACE
  fprintf(stderr, "parse_event(): buffer=%s\n", buf);
#endif

  /* look for priority */
  if (buf[i] == '<') {		/* try to get hold of priority */
    i++;
    pri = atoi(buf + i);

    while (isdigit(buf[i]) && i < 5) {
      i++;
    }

    if (buf[i] == '>') {
      i++;
    } else {
      i = 0;
      pri = DEFAULT_PRI;
    }
  }

  message = buf + i;
#ifdef TRACE
  fprintf(stderr, "parse_event(): priority=%d, message=%s\n", pri, message);
#endif

  /* look for date */
  /*                                           0123456789012345  */
  /* date prefix has the following structure: "XXX XX XX:XX:XX " */
  if (strlen(buf + i) > 16) {
    if ((buf[i + 3] == ' ') && (buf[i + 6] == ' ') && (buf[i + 9] == ':') && (buf[i + 12] == ':') && (buf[i + 15] == ' ')) {
      i += 16;
    }
  }

  message = buf + i;
#ifdef TRACE
  fprintf(stderr, "parse_event(): skipped date, message=%s\n", message);
#endif

  j = i;
  /* does this look like a symbolic hostname ? */
  while ((buf[i] != '\0') && (isalnum(buf[i]) || buf[i] == '.' || buf[i] == '-')) {
    i++;
  }
  if (isspace(buf[i])) {
    i++;
  } else {
    i = j;
  }

#ifdef TRACE
  fprintf(stderr, "parse_event(): skipped hostname, message=%s\n", message);
#endif

  j = i;
  /* try and find the : after service[pid]: */
  while ((buf[i] != '\0') && (buf[i] != ':') && (!isspace(buf[i]))) {
    switch (buf[i]) {
    case '[':
      k = i;
      pid = atoi(buf + i + 1);
      break;
    case ']':
      break;
    }
    i++;
  }
  if ((buf[i] == ':') || (pid > 0)) {	/* sensible modern syslog:  <pri>...service[pid]: */
    if (k > 0) {
      buf[k] = '\0';
    } else {
      buf[i] = '\0';
    }
    service = buf + j;
    i++;
    if (isspace(buf[i])) {
      i++;
    }
    message = buf + i;
  }
#ifdef TRACE
  fprintf(stderr, "parse_event(): tried to get service=%s, message=%s\n", service, message);
#endif

  result += idsa_event_syslog(evt, pri, message);
  if (service) {
    result += idsa_service(evt, service);
    if (pid) {
      result += idsa_pid(evt, pid);
    }
  }
  result += parse_extra(evt, service ? service : "syslog", message);

#ifdef TRACE
  idsa_event_dump(evt, stderr);
#endif

  return result;
}

#ifdef STANDALONE
#include <idsa_internal.h>
int main(int argc, char **argv)
{
  IDSA_EVENT *e;

  if (argc <= 1) {
    return 1;
  }

  e = idsa_event_new(0);
  if (e == NULL) {
    return 1;
  }

  idsa_request_init(e, "foo", "bar", "baz");

  parse_event(e, argv[1]);

  idsa_event_dump(e, stdout);

  idsa_event_free(e);

  return 0;
}
#endif
