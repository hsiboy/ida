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

#define PIPE_SCHEME  "idsa"
#define PIPE_SERVICE "idsapipe"
/* hmm, that should be a proper define */
#define PIPE_BUFFER   16*IDSA_M_MESSAGE

static int signum = 0;

static void handle(int s)
{
  if (signum != SIGALRM) {	/* alarm signals are too important to lose */
    signum = s;
  }
}

int main(int argc, char **argv)
{
  IDSA_CONNECTION *con;
  IDSA_EVENT *evt;
  char evtbuffer[IDSA_M_MESSAGE];
  int evtlen = 0;

  char outbuffer[PIPE_BUFFER];
  int outlen = 0;

  int rr, wr, sw;
  pid_t pid;
  int status;

  int nullfd;
  int pipefd[2];
  int outfd = (-1);

  IDSA_PRINT_HANDLE *ph = NULL;

  int custom = 0;
  int run = 1;
  int drain = 1;
  int offset = 0;
  int i, j;
  struct sigaction sag;

  int reset = 1;
  int timeout = 0;
  int cntmax = 0;
  int cnti = 0;
  int nul = 0;
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
	  printf("usage: %s [-n] [-f format] [-F custom format] [-i user] [-r directory] [-[t|T] timeout] [-c count] command options ...\n", argv[0]);
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
  /* done with prelim parse */

  if (dolog) {
    con = idsa_open(PIPE_SERVICE, NULL, 0);
    if (con) {
      /* make PIPE_SCHEME the default scheme for all other events */
      evt = idsa_event(con);
      if (evt) {
	idsa_scheme(evt, PIPE_SCHEME);
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
      case 'c':		/* number of events before timeout */
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  cntmax = atoi(argv[i] + j);
	  if (cntmax == 0) {
	    scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "%s is not a valid count", argv[i] + j);
	    exit(1);
	  }
	  i++;
	  j = 1;
	} else {
	  scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-c option requires an event count as parameter\n");
	  exit(1);
	}
	break;
      case 'F':		/* custom output format */
	custom = 1;
	/* fall through */
      case 'f':		/* output format */
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  ph = custom ? idsa_print_parse(argv[i] + j) : idsa_print_format(argv[i] + j);
	  if (ph == NULL) {
	    scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, "unknown output format");
	    exit(1);
	  }
	  i++;
	  j = 1;
	} else {
	  scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "-f option requires an output format as parameter");
	  exit(1);
	}
	custom = 0;
	break;
      case 'i':		/* identity to run as */
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
      case 'r':		/* chroot directory */
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
      case 'T':		/* timeout without reset */
	reset = 0;
	/* fall */
      case 't':		/* timeout with reset */
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
      offset = i;
      i = argc;
    }
  }

  if (ph == NULL) {		/* better pick a default */
    ph = idsa_print_format("internal");
    if (ph == NULL) {
      scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "unknown default output format");
      exit(1);
    }
  }
  sag.sa_handler = handle;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = 0;		/* don't restart so that we can bomb in read */

  if (timeout) {		/* if we set timeouts, we'd better catch them */
    sigaction(SIGALRM, &sag, NULL);
  }
  sigaction(SIGCHLD, &sag, NULL);

  if (offset == 0) {
    if (isatty(STDERR_FILENO)) {
      fprintf(stderr, "%s: require something to execute\n", argv[0]);
    }
    scheme_error_usage(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, "require something to execute\n");
    exit(1);
  }
  drop_root(argv[0], id, rootdir);

  evt = idsa_event_new(0);
  if (evt == NULL) {
    scheme_error_system(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "event_allocate", NULL);
    exit(1);
  }
#ifdef TRACE
  fprintf(stderr, "main(): will exec starting at [%d]=%s, %d parameters\n", offset, argv[offset], argc - offset);
#endif

  /* main loop */

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

	  if (outfd < 0) {
	    if (pipe(pipefd)) {
	      scheme_error_system(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "pipe", NULL);
	    } else {
	      pid = fork();
	      switch (pid) {
	      case -1:
		scheme_error_system(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "fork_child", NULL);
		close(pipefd[0]);
		close(pipefd[1]);
		break;
	      case 0:

		close(pipefd[1]);
		if (pipefd[0] != STDIN_FILENO) {
		  dup2(pipefd[0], STDIN_FILENO);
		  close(pipefd[0]);
		}

		if (nul) {
		  nullfd = open("/dev/null", O_RDWR);
		  if (nullfd >= 0) {
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
		execvp(argv[offset], &(argv[offset]));

		scheme_error_system(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_UNKNOWN, errno, "exec_child", NULL);
		exit(1);
		break;
	      default:
		/* might have to make output nonblocking, or is that done in server ? */
		close(pipefd[0]);
		outfd = pipefd[1];
		if (timeout) {	/* set first timeout */
		  alarm(timeout);
		}
		cnti = 0;
		break;
	      }

	    }
	  }			/* tried to allocate new fd */
	  if (outfd >= 0) {	/* check we have a child to write to */
	    if (reset && timeout) {
	      alarm(timeout);
	    }
	    sw = idsa_print_do(evt, ph, outbuffer + outlen, PIPE_BUFFER);
	    if (sw > 0) {
	      sw += outlen;
	      wr = write(outfd, outbuffer, sw);
	      if (wr == sw) {
		outlen = 0;
	      } else if (wr > 0) {
		outlen = sw - wr;
		memmove(outbuffer, outbuffer + wr, outlen);
	      }
	    } else {
	      scheme_error_protocol(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, "unable to decode message");
	      outlen = 0;
	    }

	    if (cntmax) {	/* check if we reached item limit */
	      cnti++;
	      if (cnti >= cntmax) {
		if (outlen > 0) {
		  scheme_error_protocol(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, "discarding message fragment");
		  outlen = 0;
		}
		close(outfd);
		outfd = (-1);
	      }
	    }
	  } else {
	    scheme_error_protocol(con, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_TOTAL, "unable to open pipe to child");
	    run = 0;
	  }
	}			/*  wrote event if possible */

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
      /* alarm, close fd if required */
      if (outfd >= 0) {
	if (outlen > 0) {
	  scheme_error_protocol(con, 0, IDSA_R_PARTIAL, IDSA_R_NONE, IDSA_R_PARTIAL, "discarding message fragment");
	  outlen = 0;
	}
	close(outfd);
	outfd = (-1);
      }
      signum = 0;
      break;
    case SIGCHLD:
      while (waitpid(-1, &status, WNOHANG) > 0);
      /* FIXME: should I check return code ? */
      signum = 0;
      break;
      /* default do nothing */
    }

    /* now read something from input */
    rr = read(STDIN_FILENO, evtbuffer + evtlen, IDSA_M_MESSAGE - evtlen);
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
  }				/* end of main loop */

  if (ph) {
    idsa_print_free(ph);
  }

  return 0;
}

/* use */
