
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>

#define VALUE_ONE 24
char *value_one_table[VALUE_ONE] = {
  "alpha", "beta", "gamma", "delta",
  "epsilon", "zeta", "eta", "theta",
  "iota", "kappa", "lambda", "mu",
  "nu", "xi", "omicron", "pi",
  "rho", "sigma", "tau", "upsilon",
  "phi", "chi", "psi", "omega"
};

#define FIELD_MAX 8
struct field_munger {
  int name;
  int probability;

  int subspace;
  int position;
  int mobility;
};

#define DEFAULT_FREQ 200

#include <idsa_internal.h>

void usage()
{
  printf("usage: scaffold [-t] [-s seed] [-c count] [-m mode] \"rule chain\"\n");
  printf("modes:\n");
  printf("0    - all events are the same\n");
  printf("1    - event name varies, with some names relatively uncommon\n");
  printf("2    - some event values are correlated\n");
  printf("3    - event depend on previous one\n");
  printf("4    - time value of event varies\n");
  exit(0);
}

void same_request(IDSA_EVENT * event, int t)
{
  idsa_request_init(event, "scaffold", "scaffold", value_one_table[0]);
  if (t)
    idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
}

void simple_request(IDSA_EVENT * event, int t)
{
  int i, j;
  static int k = 0;

  if (k == 0) {
    k = 1 + rand() % 3;
  }

  i = rand() % VALUE_ONE;
  for (j = 0; j < k; j++) {
    i = rand() % (i + 1);
  }

  idsa_request_init(event, "scaffold", "scaffold", value_one_table[i]);

  if (t) {
    if (i + 2 > VALUE_ONE - k)
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "true");
    else
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
  }
}

void correlated_request(IDSA_EVENT * event, int t)
{
  static int k = 0;
  int i, j;

  if (k == 0) {
    k = 1 + rand() % (VALUE_ONE / 2);
  }

  idsa_request_init(event, "scaffold", "scaffold", value_one_table[k]);

  i = rand() % VALUE_ONE;
  idsa_add_string(event, value_one_table[1], value_one_table[i]);

  if (i < k) {
    if (rand() % DEFAULT_FREQ) {	/* some correlation */
      j = k + (rand() % (VALUE_ONE - k));
      if (t)
	idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
    } else {			/* odd case */
      if (t)
	idsa_add_scan(event, "odd", IDSA_T_FLAG, "true");
      j = rand() % k;
    }
  } else {			/* uncorrelated */
    if (t)
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
    j = rand() % VALUE_ONE;
  }
  idsa_add_string(event, value_one_table[2], value_one_table[j]);
}

void sequence_request(IDSA_EVENT * event, int t)
{
  static int k = 0;
  static int i = 0;

  if (k == 0) {
    k = 1 + rand() % (VALUE_ONE / 2);
  }

  idsa_request_init(event, "scaffold", "scaffold", value_one_table[0]);

  if (rand() % DEFAULT_FREQ) {
    i = (i + rand() % k) % VALUE_ONE;
    if (t)
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
  } else {
    i = (i + rand() % k + (VALUE_ONE - k)) % VALUE_ONE;
    if (t)
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "true");
  }
  idsa_add_string(event, value_one_table[k], value_one_table[i]);
}

char file_buffer[IDSA_M_MESSAGE];
int file_count = 0;
int file_have;

void file_request(IDSA_EVENT * event, int t)
{
  int len = 0;
  int converted = 0;

  len = read(STDIN_FILENO, file_buffer + file_have, IDSA_M_MESSAGE - file_have);

#ifdef TRACE
  fprintf(stderr, "file_request(): read %d, have %d\n", len, file_have);
#endif

  switch (len) {
  case -1:
    fprintf(stderr, "idsascaffold: read failure at event %d: %s\n", file_count, strerror(errno));
    exit(1);
    break;
  case 0:
    fprintf(stderr, "idsascaffold: last event %d\n", file_count);
    exit(1);
    break;
  default:
    file_have += len;
    converted = idsa_event_frombuffer(event, file_buffer, file_have);
    if (converted <= 0) {
      fprintf(stderr, "idsascaffold: unable to read event %d\n", file_count);
      exit(1);
    }
    if (file_have > converted) {
      memcpy(file_buffer, file_buffer + converted, file_have - converted);
      file_have -= converted;
    } else {
      file_have = 0;
    }
    if (idsa_request_check(event)) {
      fprintf(stderr, "idsascaffold: corrupted event %d\n", file_count);
      exit(1);
    }
    file_count++;
    break;
  }
}

void time_request(IDSA_EVENT * event, int t)
{
  int i;
  static int map = 0;
  static int day = 0;
  static time_t tm = 0;
  struct tm *tptr;
  int odd;

  if (!tm) {
    odd = 0;
    tm = time(NULL);
    map = (rand() % 0x3ffff) | 0x40000;
    day = rand() % 4 + 1;
#ifdef TRACE
    fprintf(stderr, "time_request(): map=%08x, day=%d\n", map, day);
#endif
  } else {
    tm += (rand() % day + 1) * 86400;
    tptr = localtime(&tm);

    tptr->tm_sec = rand() % 60;
    tptr->tm_min = rand() % 60;

    if (rand() % DEFAULT_FREQ) {
      odd = 0;
    } else {
      odd = 1;
    }

    do {
      i = rand() % 24;
    } while (((map >> i) & 0x01) == odd);

    tptr->tm_hour = i;
    tm = mktime(tptr);
  }

  idsa_request_init(event, "scaffold", "scaffold", value_one_table[day]);

  idsa_time(event, tm);

  if (t) {
    if (odd)
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "true");
    else
      idsa_add_scan(event, "odd", IDSA_T_FLAG, "false");
  }

}

void complex_request(IDSA_EVENT * event, int t)
{
  int i, j;
  static struct field_munger field_table[FIELD_MAX];
  static int used_fields = 0;

  if (used_fields == 0) {
    used_fields = 1 + rand() % (FIELD_MAX - 1);
    for (i = 0; i < used_fields; i++) {
      field_table[i].subspace = 1 + rand() % (VALUE_ONE - 1);
      field_table[i].mobility = 1 + rand() % field_table[i].subspace;
      field_table[i].position = rand() % field_table[i].subspace;

      field_table[i].probability = 1 + rand() % DEFAULT_FREQ;
      field_table[i].name = rand() % VALUE_ONE;
#ifdef TRACE
      fprintf(stderr, "complex_request(): subspace=%d, mobility=%d, name=%d\n", field_table[i].subspace, field_table[i].mobility, field_table[i].name);
#endif
    }
  }

  idsa_request_init(event, "scaffold", "scaffold", value_one_table[0]);

  for (j = 0; j < used_fields; j++) {

    if (rand() % field_table[j].probability) {
      i = (rand() % field_table[j].mobility + field_table[j].position) % field_table[j].subspace;
      field_table[j].position = i;
    } else {
      i = rand() % (VALUE_ONE - field_table[j].subspace) + field_table[j].subspace;
    }
    idsa_add_string(event, value_one_table[field_table[j].name], value_one_table[i]);
  }
}

int main(int argc, char **argv)
{
  int i = 1, j = 1;
  char *rule = NULL;
  int count = 1;
  int mode = 0;
  int tag = 0;
  int resource = 0;
#ifdef TRACE
  int debug = 0;
#endif

  IDSA_PRINT_HANDLE *ph;
  char errorbuffer[1024];
  int errorlen;
  int seed = 0;

  struct rusage ru;

  IDSA_RULE_CHAIN *c;
  IDSA_RULE_LOCAL *l;
  IDSA_EVENT *q, *p;

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'h':
	usage();
	break;
      case 'c':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	count = 0;
	if (i < argc) {
	  count = atoi(argv[i] + j);
	  i++;
	  j = 1;
	}
	if (count == 0) {
	  fprintf(stderr, "%s: -c option requires a nonzero integer as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'm':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	mode = 0;
	if (i < argc) {
	  mode = atoi(argv[i] + j);
	  i++;
	  j = 1;
	}
	break;
      case 's':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	seed = 0;
	if (i < argc) {
	  seed = atoi(argv[i] + j);
	  i++;
	  j = 1;
	}
	break;
#ifdef TRACE
      case 'd':
	debug = 1;
	j++;
	break;
#endif
      case 't':
	tag = 1;
	j++;
	break;
      case 'r':
	resource = 1;
	j++;
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
	exit(1);
	break;
      }
    } else {
      rule = argv[i];
      i++;
    }
  }

  if (seed == 0) {
    seed = getpid();
  }
  srand(seed);

  if (rule == NULL) {
    fprintf(stderr, "%s: require a rule string\n", argv[0]);
    fprintf(stderr, "%s: example syntax: '%%' module-name [module-options]* ':' 'log' 'file' '/dev/tty'\n", argv[0]);
    exit(1);
  }

  printf("%s: rule \"%s\"\n", argv[0], rule);
  printf("%s: seed %d\n", argv[0], seed);
  printf("%s: mode %d\n", argv[0], mode);
  printf("%s: count %d\n", argv[0], count);


  q = idsa_event_new(0);
  p = idsa_event_new(0);

  if (!(q && p)) {
    fprintf(stderr, "%s: unable to create events\n", argv[0]);
    exit(1);
  }

  idsa_request_init(q, "scaffold", "scaffold", argv[0]);

  c = idsa_parse_buffer(q, rule, strlen(rule), 0);
  if (c == NULL) {
    fprintf(stderr, "%s: unable to start rule chain\n", argv[0]);

    fprintf(stderr, "%s: ", argv[0]);
    fflush(stderr);

    ph = idsa_print_format("native");
    if (ph) {
      errorlen = idsa_print_do(q, ph, errorbuffer, 1023);
      errorbuffer[1023] = '\0';
      if (errorlen >= 0) {
	write(STDERR_FILENO, errorbuffer, errorlen);
      } else {
	fprintf(stderr, "unable to print error message\n");
      }
      idsa_print_free(ph);
    } else {
      fprintf(stderr, "unable to acquire print handle for error message\n");
    }
    fflush(stderr);

    exit(1);
  }

  l = idsa_local_new(c);
  if (!l) {
    fprintf(stderr, "%s: unable to start local stuff\n", argv[0]);
    exit(1);
  }

  /* phew, finally a main loop */

  for (i = 0; i < count; i++) {

    switch (mode) {
    case 0:
      same_request(q, tag);
      break;
    case 1:
      simple_request(q, tag);
      break;
    case 2:
      correlated_request(q, tag);
      break;
    case 3:
      sequence_request(q, tag);
      break;
    case 4:
      time_request(q, tag);
      break;
    case 5:
      file_request(q, tag);
      break;
    case 9:
      complex_request(q, tag);
      break;
    }

    idsa_reply_init(p);
    idsa_local_init(c, l, q, p);

#ifdef TRACE
    if (debug)
      idsa_event_dump(q, stderr);
#endif

    idsa_chain_run(c, l);

#ifdef TRACE
    if (debug)
      idsa_event_dump(p, stderr);
#endif

    idsa_local_quit(c, l);
  }

  if (resource) {
    if (getrusage(RUSAGE_SELF, &ru)) {
      fprintf(stderr, "idsascaffold: unable to get resource usage: %s\n", strerror(errno));
    } else {
      fprintf(stderr, "idsascaffold: resources: rss %ld, stack %ld, data %ld\n", ru.ru_maxrss, ru.ru_isrss, ru.ru_idrss);
    }
  }

  /* clean up */
  idsa_local_free(c, l);

  idsa_chain_stop(c);

  idsa_event_free(q);
  idsa_event_free(p);

  return 0;
}
