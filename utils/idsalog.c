#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>

#include <idsa.h>
#include <idsa_internal.h>

#define SCHEME  "idsalog"
#define NAME    "event"
#define SERVICE "idsalog"

int main(int argc, char **argv)
{
  int result = 0;

  IDSA_CONNECTION *c;
  IDSA_EVENT *e;
  int i, j, a;
  char t;
  int dump;
  unsigned int y;
  int flag;
  int quiet;

  char *service, *name, *scheme;
  char *key, *type, *value;
  char *reason;

  unsigned int arisk, crisk, irisk;

  arisk = IDSA_R_UNKNOWN;
  crisk = IDSA_R_UNKNOWN;
  irisk = IDSA_R_UNKNOWN;

  flag = 0;
  service = SERVICE;
  name = NAME;
  scheme = SCHEME;

  a = argc;			/* by default no additional fields */
  dump = 0;
  quiet = 0;

  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'v':
	printf("idsalog %s\n", VERSION);
	exit(0);
	break;
      case 'f':
	flag = 1;
	j++;
	break;
      case 'h':
	printf("Usage: %s [-d] [-q] [-f] [-s service] [-n eventname] [-m scheme] [-r[cai] risk] [key[:type]=value ...]\n", argv[0]);
	printf("Returns zero if event allowed, nonzero otherwise\n");
	printf("Most shells make the return code available in $?\n");
	exit(0);
	break;
      case 'd':
	dump++;
	j++;
	break;
      case 'q':
	quiet++;
	j++;
	break;
      case 's':
      case 'n':
      case 'm':
	t = argv[i][j];
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  switch (t) {
	  case 's':
	    service = argv[i] + j;
	    break;
	  case 'n':
	    name = argv[i] + j;
	    break;
	  case 'm':
	    scheme = argv[i] + j;
	    break;
	  }
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -%c option requires a parameter\n", argv[0], t);
	  exit(2);
	}
	break;
      case 'r':
	j++;
	t = argv[i][j];
	if (t != '\0') {
	  j++;
	  if (argv[i][j] == '\0') {
	    j = 0;
	    i++;
	  }
	  if (i < argc) {
	    switch (t) {
	    case 'a':
	      arisk = idsa_risk_parse(argv[i] + j);
	      break;
	    case 'c':
	      crisk = idsa_risk_parse(argv[i] + j);
	      break;
	    case 'i':
	      irisk = idsa_risk_parse(argv[i] + j);
	      break;
	    default:
	      fprintf(stderr, "%s: -r%c is not a valid risk\n", argv[0], t);
	      exit(2);
	      break;
	    }
	    i++;
	    j = 1;
	  } else {
	    fprintf(stderr, "%s: -r%c option requires a value between -1.0 and 1.0\n", argv[0], t);
	    exit(2);
	  }
	} else {
	  fprintf(stderr, "%s: require -ra -rc or -ri\n", argv[0]);
	  exit(2);
	}
	break;
      case '-':
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      default:
	fprintf(stderr, "%s: unknown option -%c\n", argv[0], argv[i][j]);
	exit(2);
	break;
      }
    } else {
      a = i;
      i = argc;
    }
  }

  c = idsa_open(service, NULL, IDSA_F_ENV);
  if (c) {
    e = idsa_event(c);
    if (e) {

      result += idsa_name(e, name);
      result += idsa_scheme(e, scheme);
      result += idsa_risks(e, flag, arisk, crisk, irisk);

      if (dump) {
	idsa_event_dump(e, stderr);
      }
      /*  add in key value pairs */
      while (a < argc) {
	key = argv[a];
	i = 0;
	for (i = 0; (argv[a][i] != '\0') && (argv[a][i] != '='); i++);
	if (argv[a][i] == '=') {
	  argv[a][i] = '\0';
	  i++;
	  value = argv[a] + i;

	  i = 0;
	  for (i = 0; (argv[a][i] != '\0') && (argv[a][i] != ':'); i++);
	  if (argv[a][i] == ':') {
	    argv[a][i] = '\0';
	    i++;
	    type = argv[a] + i;
	    y = idsa_type_code(type);
	  } else {
	    type = NULL;
	    y = idsa_resolve_type(IDSA_M_UNKNOWN, key);
	    if (y == IDSA_T_NULL) {
	      y = IDSA_T_STRING;
	    }
	  }

	  if (y == IDSA_T_NULL) {
	    fprintf(stderr, "%s: unknown type for %s=%s\n", argv[0], key, value);
	    result++;
	  } else {
	    if (idsa_add_scan(e, key, y, value)) {
	      fprintf(stderr, "%s: unable to scan <%s:0x%04x=%s>\n", argv[0], key, y, value);
	      result++;
	    }
	  }


	} else {
	  fprintf(stderr, "%s: require an = in %s\n", argv[0], argv[a]);
	  result++;
	}
	a++;
      }

      if (result) {
	fprintf(stderr, "%s: errors during event creation\n", argv[0]);
	result = 2;
      } else {
	result = (idsa_log(c, e) == IDSA_L_ALLOW) ? 0 : 1;

	if (!quiet) {
	  if (result) {
	    printf("denied: ");
	  } else {
	    printf("allowed: ");
	  }
	  reason = idsa_reason(c);
	  if (reason) {
	    puts(reason);
	  } else {
	    putchar('\n');
	  }
	}

      }

    } else {
      fprintf(stderr, "%s: unable to create event\n", argv[0]);
      result = 2;
    }
    idsa_close(c);
  } else {
    fprintf(stderr, "%s: unable to establish connection\n", argv[0]);
    result = 2;
  }

  return result;
}

/* use */
