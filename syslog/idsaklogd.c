#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>

#if defined(__linux__)
#include <sys/klog.h>
#endif

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include "misc.h"
#include "socketlock.h"
#include "sparse.h"

#define LOG_LINE          1025	/* buffer / line length */
#define LOG_SCHEME       "klog"
#define LOG_LOCK "/var/run/idsaklogd"

#ifdef _PATH_KLOG
#define LOG_SOURCE _PATH_KLOG
#else
#define LOG_SOURCE "/proc/kmsg"
#endif

static volatile int run = 1;
static void handle(int s)
{
  run = 0;
}

#define STATE_START     0
#define STATE_PRIORITY  1
#define STATE_MESSAGE   2
#define STATE_END       3

static int dispatch(IDSA_CONNECTION * con, char *buf, int len)
{
  int i;
  int state = STATE_START;
  int pri = 0;
  int message = 0;
  char *name = NULL;
  unsigned int ar, cr, ir;
  int result = 0;

  for (i = 0; i < len; i++) {
    switch (state) {
    case STATE_START:
      switch (buf[i]) {
      case '<':
	state = STATE_PRIORITY;
	pri = 0;
	break;
      case '\0':
	state = STATE_START;
	break;
      case '\n':
	state = STATE_START;
	break;
      default:
	state = STATE_END;
	break;
      }
      break;
    case STATE_PRIORITY:
      switch (buf[i]) {
      case '0':
	pri = 0 + pri * 10;
	break;
      case '1':
	pri = 1 + pri * 10;
	break;
      case '2':
	pri = 2 + pri * 10;
	break;
      case '3':
	pri = 3 + pri * 10;
	break;
      case '4':
	pri = 4 + pri * 10;
	break;
      case '5':
	pri = 5 + pri * 10;
	break;
      case '6':
	pri = 6 + pri * 10;
	break;
      case '7':
	pri = 7 + pri * 10;
	break;
      case '8':
	pri = 8 + pri * 10;
	break;
      case '9':
	pri = 9 + pri * 10;
	break;
      case '>':
	state = STATE_MESSAGE;
	message = i + 1;
	break;
      default:
	state = STATE_END;
	break;
      }
      break;
    case STATE_MESSAGE:
      switch (buf[i]) {
      case '\0':
      case '\n':
	buf[i] = '\0';
	name = idsa_syspri2severity(pri);
	ar = idsa_syspri2a(pri);
	cr = idsa_syspri2c(pri);
	ir = idsa_syspri2i(pri);

	idsa_set(con, name, LOG_SCHEME, 0, ar, cr, ir, "message", IDSA_T_STRING, buf + message, NULL);
	/* parse_extra(IDSA_EVENT * evt, LOG_SCHEME, buf + message); */

	state = STATE_START;
	result = i + 1;
	break;
      }
      break;
    case STATE_END:
      switch (buf[i]) {
      case '\0':
      case '\n':
	state = STATE_START;
	break;
      }
      result = i;
      break;
    }
  }

  return result;
}

int main(int argc, char **argv)
{
  int fd;
  IDSA_CONNECTION *con;

  int rr, dr, ix;
  char buffer[LOG_LINE];

  int i = 1, j = 1;

  char *id = NULL;
  char *rootdir = NULL;

  int console = 0;
  int zap = 0;
#ifdef TRACE
  int nofork = 1;
#else
  int nofork = 0;
#endif

  struct sigaction sag;
  int error;

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2002 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("usage: %s [-knp] [-i user] [-r directory]\n", argv[0]);
	exit(0);
	break;
      case 'i':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  id = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -i option requires a user id as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'r':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  rootdir = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -r option requires a directory as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'p':
	console++;
	j++;
	break;
      case 'k':
	zap++;
	j++;
	break;
      case 'n':
	nofork++;
	j++;
	break;
      case 'v':
	printf("idsaklogd %s\n", VERSION);
	exit(0);
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
      fprintf(stderr, "%s: unknown argument %s\n", argv[0], argv[i]);
      exit(1);
    }
  }

  sag.sa_handler = handle;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = 0;		/* TERM and ALRM are supposed to interrrupt us */
  sigaction(SIGTERM, &sag, NULL);
  sigaction(SIGINT, &sag, NULL);
  sigaction(SIGSEGV, &sag, NULL);

  if (nofork == 0) {
    fork_parent(argv[0]);
  }

  if (!console) {
    klogctl(6, NULL, 0);
  }

  fd = open(LOG_SOURCE, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "%s: unable to open %s: %s\n", argv[0], LOG_SOURCE, strerror(errno));
    exit(1);
  }

  if (socketlock(LOG_LOCK, zap)) {
    fprintf(stderr, "%s: unable to acquire lock: %s\n", argv[0], strerror(errno));
    exit(1);
  }

  con = idsa_open(LOG_SCHEME, NULL, IDSA_F_ENV);
  if (con == NULL) {
    fprintf(stderr, "%s: unable to connect to idsad\n", argv[0]);
    exit(1);
  }

  drop_root(argv[0], id, rootdir);
  drop_fork(argv[0]);

  if (nofork == 0) {
    fflush(stderr);
    fclose(stderr);
    close(STDERR_FILENO);
  }

  ix = 0;

  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_SUCCESS, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTART, "version", IDSA_T_STRING, VERSION, NULL);

  while (run) {
    rr = read(fd, buffer + ix, LOG_LINE - (1 + ix));
    switch (rr) {
    case -1:
      if (errno != EINTR) {
	error = errno;
	idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SFAIL, "read", IDSA_T_ERRNO, &error, NULL);
	run = 0;		/* quit */
      }
      break;
    case 0:
      run = 0;			/* quit */
      break;
    default:
      buffer[rr] = '\0';
      dr = dispatch(con, buffer, rr);
      if ((dr <= 0) || (rr <= dr)) {
	ix = 0;
      } else {
	memmove(buffer, buffer + dr, rr - dr);
	ix = rr - dr;
      }
      break;
    }
  }

  klogctl(7, NULL, 0);

  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTOP, "version", IDSA_T_STRING, VERSION, NULL);

  close(fd);
  idsa_close(con);

  return 0;
}
