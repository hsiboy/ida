#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <idsa_internal.h>
#include "misc.h"
#include "scheme.h"

#define EXEC_SCHEME  "idsa"
#define EXEC_SERVICE "idsaexec"

static volatile int signum = 0;

static void handle(int s)
{
  signum = s;
}

int main(int argc, char **argv)
{
  IDSA_CONNECTION *con;
  IDSA_EVENT *evt;
  IDSA_UNIT *unt;
  char evtbuffer[IDSA_M_MESSAGE];
  char parmbuffer[IDSA_M_MESSAGE];
  int rr;
  pid_t pid;
  int status;
  int nullfd;

  int timeout = 0;
  int parmlen = 0;
  int evtlen = 0;
  int run = 1;
  int drain = 1;
  int offset = 0;
  char **exv = NULL;
  int exc = 0;
  char **parmv = NULL;
  int parmc = 0;
  int *map = NULL;
  int i, j;
  struct sigaction sag;
  sigset_t sst;

  int nul = 0;
  int syn = 0;
  int dolog = 0;
  char *id = NULL;
  char *rootdir = NULL;

  /* prelimiary look at commandline, just to check if we need to log */
  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	if (isatty(STDOUT_FILENO)) {
	  printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	  exit(0);
	}
	j++;
	break;
      case 'h':
	if (isatty(STDOUT_FILENO)) {
	  printf("usage: %s [-lns] [-i user] [-r directory] [-t timeout] command options ...\n", argv[0]);
	  exit(0);
	}
	j++;
	break;
      case 'l':
	dolog++;
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      case '-':
      default:
	j++;
	break;
      }
    } else {
      i++;
    }
  }

  if (dolog) {
    con = idsa_open(EXEC_SERVICE, NULL, 0);
    if (con) {
      /* make EXEC_SCHEME the default scheme for all other events */
      evt = idsa_event(con);
      if (evt) {
	idsa_scheme(evt, EXEC_SCHEME);
	idsa_template(con, evt);
      }
    }
  } else {
    con = NULL;
  }

  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
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
	  scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-i option requires user name as parameter");
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
	  scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-r option requires a directory as parameter");
	  exit(1);
	}
	break;
      case 't':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  timeout = atoi(argv[i] + j);
	  if (timeout == 0) {
	    scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "%s is not a valid timeout", argv[i] + j);
	    exit(1);
	  }
	  i++;
	  j = 1;
	} else {
	  scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-t option requires a time value in seconds as parameter\n");
	  exit(1);
	}
	break;
      case 'l':
	dolog++;
	j++;
	break;
      case 'n':
	nul++;
	j++;
	break;
      case 's':
	syn++;
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
	scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-%c is not a valid option\n", argv[i][j]);
	exit(1);
	break;
      }
    } else {
#ifdef TRACE
      fprintf(stderr, "main(): found offset\n");
#endif
      offset = i;
      i = argc;
    }
  }

  sigemptyset(&sst);

  sag.sa_handler = handle;
  sigemptyset(&(sag.sa_mask));
  sag.sa_flags = 0;

  if (timeout) {		/* if we set timeouts, we'd better catch them */
    sigaddset(&sst, SIGALRM);
    sigaction(SIGALRM, &sag, NULL);
  }

  sigaddset(&sst, SIGCHLD);
  sigaction(SIGCHLD, &sag, NULL);

  sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child and alarm for everything execpt read and wait */

  if (offset == 0) {
    scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "require something to execute\n");
    exit(1);
  }
  drop_root(argv[0], id, rootdir);

  evt = idsa_event_new(0);
  if (evt == NULL) {
    scheme_error_system(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "event_allocate", NULL);
    exit(1);
  }
  exc = argc - offset;
  exv = malloc(sizeof(char *) * (exc + 1));

  if (exv == NULL) {
    scheme_error_system(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "buffer_allocate", NULL);
    exit(1);
  }
  parmc = 0;

  for (i = 0; i < exc; i++) {
    exv[i] = argv[offset + i];
    if (exv[i][0] == '%') {
      parmc++;
    }
  }
  exv[i] = NULL;

  if (parmc) {
    map = malloc(sizeof(int) * parmc);
    parmv = malloc(sizeof(char *) * (parmc));

    if (map == NULL || parmv == NULL) {
      scheme_error_system(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "buffer_allocate", NULL);
      exit(1);
    }
    for (i = 0, j = 0; i < exc; i++) {
      if (exv[i][0] == '%') {
	map[j] = i;
	parmv[j] = exv[i] + 1;
	j++;
      }
    }
  }
#ifdef TRACE
  for (i = 0; i < parmc; i++) {
    fprintf(stderr, "main(): need to look up [%d]=%s\n", map[i], parmv[i]);
  }
#endif

#ifdef TRACE
  fprintf(stderr, "main(): will exec starting at [%d]=%s, %d parameters\n", offset, argv[offset], exc);
#endif

  while (run) {

    if (evtlen > 0) {
      drain = 1;
    }
    while (drain) {		/* chance of reading something */
      rr = idsa_event_frombuffer(evt, evtbuffer, evtlen);
#ifdef TRACE
      fprintf(stderr, "main(): decoding event %d/%d\n", rr, evtlen);
#endif
      if (rr > 0) {
	if (rr < evtlen) {
	  memmove(evtbuffer, evtbuffer + rr, evtlen - rr);
	  evtlen -= rr;
	  drain = 1;
	} else {
	  drain = 0;
	  evtlen = 0;
	}

	if (idsa_request_check(evt)) {
	  scheme_error_protocol(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_TOTAL, "received corrupted event");
	  run = 0;
	} else {
	  parmlen = 0;
	  for (i = 0; i < parmc; i++) {
	    unt = idsa_event_unitbyname(evt, parmv[i]);
	    if (unt) {
	      rr = idsa_unit_print(unt, parmbuffer + parmlen, IDSA_M_MESSAGE - (parmlen + 1), 0);
	      if (rr >= 0) {
		exv[map[i]] = parmbuffer + parmlen;
		parmlen += rr;
		parmbuffer[parmlen] = '\0';
#ifdef TRACE
		fprintf(stderr, "main(): parameter [%d]=%d is <%s>\n", i, map[i], exv[map[i]]);
#endif
		parmlen++;
	      } else {
		scheme_error_protocol(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, "unable to print unit %s ", parmv[i]);
	      }
	    } else {
	      scheme_error_protocol(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, "unit %s not found", parmv[i]);
	    }
	  }

#ifdef TRACE
	  fprintf(stderr, "main(): supposed to exec:");
	  for (i = 0; i < exc; i++) {
	    fprintf(stderr, " %s", exv[i]);
	  }
	  fprintf(stderr, "\n");
#endif
	  pid = fork();
	  switch (pid) {
	  case -1:
	    scheme_error_system(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "fork_child", NULL);
	    break;
	  case 0:
	    sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable signals */
	    if (timeout) {
	      alarm(timeout);
	    }
	    close(STDIN_FILENO);

	    if (nul) {
	      nullfd = open("/dev/null", O_RDWR);
	      if (nullfd >= 0) {
		if (nullfd != STDIN_FILENO) {
		  dup2(nullfd, STDIN_FILENO);
		}
		if (nullfd != STDOUT_FILENO) {
		  dup2(nullfd, STDOUT_FILENO);
		}
		if (nullfd != STDERR_FILENO) {
		  dup2(nullfd, STDERR_FILENO);
		}
		if (nullfd > STDERR_FILENO) {
		  close(nullfd);
		}
	      }
	    }
	    execvp(exv[0], exv);

	    scheme_error_system(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "exec_child", NULL);
	    exit(1);
	    break;
	  default:
	    if (syn) {
	      sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable alarm signal */
	      if (timeout) {	/* give child 1s to react to alarm */
		alarm(timeout + 1);
	      }
	      if (waitpid(pid, &status, 0) < 0) {
		if (timeout) {
		  kill(pid, SIGTERM);
		}
	      } else {
		/* FIXME: should I look at return code ? */
	      }
	      sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child|alarm signal */
	    }
	    break;
	  }
	}
      } else {
	drain = 0;
	if (evtlen >= IDSA_M_MESSAGE) {	/* full, this had to be an event */
	  scheme_error_protocol(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_TOTAL, "received oversized event");
	  run = 0;
	}
      }
    }

    switch (signum) {
    case SIGALRM:
      /* child has already exited, just reset signal */
      signum = 0;
      break;
    case SIGCHLD:
      while (waitpid(-1, &status, WNOHANG) > 0);
      /* FIXME: should I check return code ? */
      signum = 0;
      break;
      /* default do nothing */
    }

    sigprocmask(SIG_UNBLOCK, &sst, NULL);	/* enable child signal */
    rr = read(STDIN_FILENO, evtbuffer + evtlen, IDSA_M_MESSAGE - evtlen);
    sigprocmask(SIG_BLOCK, &sst, NULL);	/* disable child signal */

#ifdef TRACE
    fprintf(stderr, "main(): readresult %d/%d\n", rr, IDSA_M_MESSAGE - evtlen);
#endif
    if (rr > 0) {
      evtlen += rr;
    } else {
      if (rr == 0) {		/* EOF */
	run = 0;
      } else {
	switch (errno) {
	case EAGAIN:
	case EINTR:
	  /* we can cope with these errors */
	  break;
	default:
	  scheme_error_system(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "read_event", NULL);
	  run = 0;
	  break;
	}
      }
    }				/* end of read STDIN section */
  }

  return 0;
}

/* use */
