#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <idsa.h>

#include "udomain.h"
#include "misc.h"

#include "idsad.h"
#include "structures.h"
#include "functions.h"

static void handle(int s);

volatile int signum = 0;

void usage()
{
  printf("idsad %s\n", VERSION);
  printf("Usage: idsad [-knuv] [-f file] [-i username] [-M integer] [-m integer] [-p socket ...] [-r directory]\n");
  printf("-f file          use alternate configuration file (default is %s)\n", IDSAD_CONFIG);
  printf("-i username      run as this username (no default)\n");
  printf("-k               kill existing idsad instance (instead of lockfile)\n");
  printf("-M integer       preallocate a connection table of given size\n");
  printf("-m integer       grow connection table when needed to given size\n");
  printf("-n               do not fork into background\n");
  printf("-p socket ...    whitespace delimited list of unix domain sockets to listen on (default is %s)\n", IDSA_SOCKET);
  printf("-r directory     chroot to directory (no default)\n");
  printf("-u               honour umask when creating sockets\n");
  printf("-v               print version\n");

  exit(0);
}

#define COPY_BUFFER 128

static void handle(int s)
{
  if (signum != SIGTERM) {	/* TERM is too important to overwrite */
    signum = s;
  }
}

#ifndef MAXUID
#define MAXUID 65535
#endif

static void prune(STATE_SET * set)
{
  JOB *job;
  uid_t uidlow, uidnext;
  int i;
  int count;
  int start;
  int ignore;

  /* WARNING: assumes nonzero set->s_jobquota, otherwise drops everything */

  message_error_internal(set, "too many connections, enforcing quotas");

  /* get lowest nonroot uid */
  uidnext = MAXUID;
  for (i = 0; i < set->s_jobcount; i++) {
    job = &(set->s_jobs[i]);
    if ((job->j_uid > 0) && (uidnext > job->j_uid)) {
      uidnext = job->j_uid;
    }
  }

#ifdef TRACE
  fprintf(stderr, "prune(): lowest candidate uid is %d\n", uidnext);
#endif

  ignore = 0;
  while (uidnext < MAXUID) {
    start = 1;
    uidlow = uidnext;
    uidnext = MAXUID;
    count = 0;
    /* start with first job not smaller than uid under consideration */
    for (i = ignore; i < set->s_jobcount; i++) {
      job = &(set->s_jobs[i]);
      if (job->j_uid < uidlow) {	/* if smaller */
	if (start)
	  ignore++;		/* if at start, move start position for next inner */
      } else if (job->j_uid == uidlow) {	/* equal */
	if (start)
	  ignore++;		/* if not encountered larger uid, can move start */
	count++;
	if (count >= set->s_jobquota) {	/* exceeded quota, start dropping things */
	  job->j_state = JOB_STATEFIN;
	}
      } else {			/* larger */
	start = 0;		/* from now on start can not be moved */
	if (job->j_uid < uidnext) {	/* candidate for next outer loop */
	  uidnext = job->j_uid;
	}
      }
    }
  }

}

int main(int argc, char **argv)
{
  int mfd, smfd, sr;		/* variables for select */
  fd_set fsr, fsw;

  int lc, *ltable;		/* listen variables */
  JOB *j, *jtmp;		/* job variables */

  STATE_SET *set;		/* almost all state kept here */

  int run;			/* control mainloop */
  pid_t peer;			/* pid of peer to be killed */
  mode_t mask;			/* the mask */
  int status;			/* return status of exited child */
  struct sigaction sag;		/* need fine grained control over signals */

  char *config;			/* name of config file */
  char *rootdir;		/* directory to do a chroot to */
  int nofork;			/* don't fork into background (default: fork) */
  int noumask;			/* disable umask when creating sockets (default: ignore umask) */
  char *id;			/* string containing user name */
  int zap;			/* kill any running instance before starting */

  int max, start, quota;	/* number of clients: maximum/start/per user */

  int i, k, t;			/* misc */

  /* cmdline defaults */
  id = NULL;
  config = NULL;
  rootdir = NULL;
  noumask = 1;
  zap = 0;

  /* defaults */
  quota = IDSAD_JOBQUOTA;
  start = IDSAD_JOBSTART;
  max = 2 * getdtablesize() / 3;
  if (max < IDSAD_JOBSTART) {	/* getdtablesize returned something unrealistic */
    max = IDSAD_JOBSTART;	/* fall back to the small startup value */
  }
#ifdef TRACE
  nofork = 1;
#else
  nofork = 0;
#endif

  ltable = NULL;
  lc = 0;
  signum = 0;

  /* set to keep -Wall -O2 happy */
  mask = 0;
  peer = 0;

  /* nontrivial initialization: */
  /* 1) provisional argument parsing */
  /* 2) possibly fork into background, with parent() watching stderr */
  /* 3) real argument parsing */
  /* 4) fill in defaults */
  /* 5) parse config file */
  /* 6) drop root and chroot */
  /* 7) signal handlers */

#ifdef TRACE
  mtrace();
#endif

  /* provisional parse */
  i = 1;
  k = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][k]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':		/* print brief help message */
	usage();
	break;
      case 'k':		/* kill any existing instance */
	zap++;
	k++;
	break;
      case 'n':		/* keep in foreground */
	nofork++;
	k++;
	break;
      case 'u':
	noumask = 0;
	k++;
	break;
      case 'v':
	printf("idsad %s\n", VERSION);
	exit(0);
	break;
      case '\0':
	k = 1;
	i++;
	break;
      default:
	k++;
	break;
      }
    } else {
      i++;
    }
  }

  if (nofork == 0) {
    /* go into background, stderr is now a pipe to parent */
    fork_parent(argv[0]);
  }

  /* don't panic in case other end goes away */
  sag.sa_handler = SIG_IGN;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = SA_RESTART;
  sigaction(SIGPIPE, &sag, NULL);

  if (noumask) {
    /* clear out umask */
    mask = umask(S_IXUSR | S_IXGRP | S_IXOTH);
  }
  mfd = 0;
  i = 1;
  k = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][k]) {
      case 'p':
	k++;
	if (argv[i][k] == '\0') {
	  k = 0;
	  i++;
	}
	while ((i < argc) && (argv[i][k] != '-')) {
	  ltable = realloc(ltable, sizeof(int) * (lc + 1));
	  if (ltable) {
	    ltable[lc] = udomainlisten(argv[i] + k, IDSAD_BACKLOG, zap);
	    if (ltable[lc] == (-1)) {
	      fprintf(stderr, "idsad: unable to listen on socket %s: %s\n", argv[i] + k, strerror(errno));
	      exit(1);
	    }
	    if (ltable[lc] > mfd) {
	      mfd = ltable[lc];
	    }
	    lc++;
	    k = 0;
	    i++;
	  } else {
	    fprintf(stderr, "idsad: unable to allocate listen socket table of %d elements\n", lc + 1);
	    exit(1);
	  }

	}
	break;
      case 'i':
	k++;
	if (argv[i][k] == '\0') {
	  k = 0;
	  i++;
	}
	if (i < argc) {
	  id = argv[i] + k;
	  i++;
	  k = 1;
	} else {
	  fprintf(stderr, "idsad: -i option requires a user id as parameter\n");
	  exit(1);
	}
	break;
      case 'f':
	k++;
	if (argv[i][k] == '\0') {
	  k = 0;
	  i++;
	}
	if (i < argc) {
	  config = argv[i] + k;
	  i++;
	  k = 1;
	} else {
	  fprintf(stderr, "idsad: -f option requires a configuration file as parameter\n");
	  exit(1);
	}
	break;
      case 'r':
	k++;
	if (argv[i][k] == '\0') {
	  k = 0;
	  i++;
	}
	if (i < argc) {
	  rootdir = argv[i] + k;
	  i++;
	  k = 1;
	} else {
	  fprintf(stderr, "idsad: -r option requires a directory as parameter\n");
	  exit(1);
	}
	break;
      case 'M':
	start = 0;
	/* WARNING : fall */
      case 'm':
	k++;
	if (argv[i][k] == '\0') {
	  k = 0;
	  i++;
	}
	if (i >= argc) {
	  fprintf(stderr, "idsad: -r option requires a directory as parameter\n");
	  exit(1);
	}
	max = atoi(argv[i] + k);
	if (max <= 0) {
	  fprintf(stderr, "idsad: -m option requires a nonzero integer as parameter\n");
	  exit(1);
	}
	if (max + 1 > getdtablesize()) {
	  fprintf(stderr, "idsad: using an unreasonable connection table size may prevent quotas from working\n");
	}
	i++;
	k = 1;
	break;
	/* these options have already been handled */
      case 'v':
      case 'u':
      case 'n':
      case 'k':
      case 'h':
      case 'c':
      case '-':
	k++;
	break;
      case '\0':
	k = 1;
	i++;
	break;
      default:
	fprintf(stderr, "idsad: unknown option -%c\n", argv[i][k]);
	exit(1);
	break;
      }
    } else {
      fprintf(stderr, "idsad: unknown argument %s\n", argv[i]);
      exit(1);
    }
  }

  if ((start <= 0) || (start > max)) {
    start = max;
  }
  if (quota >= max) {
    quota = 1;
  }

  /* build set of rules soon since it is most likely cause of errors */
  set = set_new(max, start, quota);
  if (set == NULL) {
    fprintf(stderr, "idsad: unable to allocate memory for state\n");
    exit(1);
  }

  if (set_parse(set, config ? config : IDSAD_CONFIG)) {
    fprintf(stderr, "idsad: rule initialisation failed\n");
    message_stderr(set);
    exit(1);
  }

  /* in case there was some warning during libidsa setup */
  message_chain(set);

  /* if user has not specified a socket we listen on default */
  if (lc == 0) {
    ltable = malloc(sizeof(int));
    if (ltable) {
      ltable[0] = udomainlisten(IDSA_SOCKET, IDSAD_BACKLOG, zap);
      if (ltable[0] != (-1)) {
	mfd = ltable[0];
	lc = 1;
      } else {
	fprintf(stderr, "idsad: unable to listen on socket %s: %s\n", IDSA_SOCKET, strerror(errno));
	exit(1);
      }
    } else {
      fprintf(stderr, "idsad: unable to allocate memory for an integer\n");
      exit(1);
    }
  }
  if (noumask) {
    umask(mask);
  }
  drop_root("idsad", id, rootdir);
  drop_fork("idsad");

  /* cache our own uid */
  set->s_gid = getgid();

  sag.sa_handler = handle;
/*  sag.sa_sigaction = NULL;*/
  sigfillset(&(sag.sa_mask));

  sag.sa_flags = SA_RESTART;	/* minor ones */
  sigaction(SIGCHLD, &sag, NULL);
  sigaction(SIGHUP, &sag, NULL);

/*  signal(SIGCHLD, handle);*/
/*  signal(SIGHUP, handle);*/

  sag.sa_flags = 0;		/* serious signals */
  sigaction(SIGINT, &sag, NULL);
  sigaction(SIGTERM, &sag, NULL);
  sigaction(SIGALRM, &sag, NULL);

/*  signal(SIGTERM, handle);*/
/*  signal(SIGALRM, handle);*/

#ifdef TRACE
  fprintf(stderr, "main(): starting up\n");
#endif

  /* close stderr, parent will notice and go away */
  if (nofork == 0) {
    fflush(stderr);
    fclose(stderr);
    close(STDERR_FILENO);
  }

  if (zap) {			/* give previous instance a chance to quit before writing */
    sched_yield();
  }
  message_start(set, VERSION);

  /* enter main loop */
  run = 1;
  do {

    /* all signals indicate an abnormal condition including SIGCHLD */
    /* none of our children should die. Hence we do not worry about */
    /* loosing signals if several delivered */

    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifdef TRACE
      fprintf(stderr, "main(): received TERM signal\n");
#endif
      run = 0;
      signum = 0;
      /* give us a second before interrupting select */
      alarm(1);
      break;
    case SIGHUP:
      signum = 0;
      message_error_internal(set, "hangup signal ignored");
      break;
    case SIGALRM:		/* ha, this should never happen */
      signum = 0;
      run = 0;
      break;
    case SIGCHLD:
      /* FIXME: maybe report this too ? */
      while (waitpid(-1, &status, WNOHANG) > 0);
      message_error_internal(set, "child signal ignored");
      signum = 0;
      break;
    }

    FD_ZERO(&fsr);
    FD_ZERO(&fsw);

    /* listen sockets */
    for (i = 0; i < lc; i++) {
      FD_SET(ltable[i], &fsr);
    }

    /* connected sockets */
    for (i = 0; i < set->s_jobcount; i++) {
      j = &(set->s_jobs[i]);

      FD_SET(j->j_fd, &fsr);	/* add all to read list */

      if (job_iswrite(j)) {	/* add those who have something to write list */
	FD_SET(j->j_fd, &fsw);
      }
    }

    sr = select(mfd + 1, &fsr, &fsw, NULL, NULL);
    set->s_time = time(NULL);

    if (sr > 0) {

      /* try to accept a new connection */
      for (i = 0; i < lc; i++) {
	if (FD_ISSET(ltable[i], &fsr)) {
	  if ((set->s_jobcount >= set->s_jobsize) && (set->s_jobsize < set->s_jobmax)) {	/* make space for new slot if required */
	    t = ((2 * set->s_jobsize) < set->s_jobmax) ? 2 * set->s_jobsize : set->s_jobmax;
	    jtmp = realloc(set->s_jobs, sizeof(JOB) * t);
	    if (jtmp) {
	      set->s_jobs = jtmp;
	      set->s_jobsize = t;
	    } else {		/* no space */
	      message_error_system(set, errno, "unable to service a new client because of memory limitations");
	    }
	  }
	  if (set->s_jobcount < set->s_jobsize) {
	    j = &(set->s_jobs[set->s_jobcount]);
	    if (job_accept(j, ltable[i]) == 0) {
	      if (message_connect(set, j->j_pid, j->j_uid, j->j_gid) == IDSA_CHAIN_DROP) {	/* instruction to drop connection */
		j->j_state = JOB_STATEFIN;
	      }
	      if (mfd < j->j_fd) {	/* win: update mfd as little as possible ;-) */
		mfd = j->j_fd;
	      }
	      set->s_jobcount++;
	    } else {
	      message_error_system(set, errno, "unable to service a new client because of accept failure");
	    }
	  } else {		/* should not happen. But if then we drop otherwise select comes back immediately = busy loop */
	    job_drop(ltable[i]);
	    /* message_error_internal(set, "unable to service a new client because of accept failure"); */
	  }
	}
      }				/* end of handling listeners */

      /* handle connected sockets */
      for (i = 0; i < set->s_jobcount; i++) {
	j = &(set->s_jobs[i]);

	if (FD_ISSET(j->j_fd, &fsw)) {	/* drain out write buffer */
#ifdef TRACE
	  fprintf(stderr, "main(): write activity on client, fd=<%d>\n", j->j_fd);
#endif
	  job_write(j);
	}
	if (FD_ISSET(j->j_fd, &fsr)) {	/* fill in read buffer */
#ifdef TRACE
	  fprintf(stderr, "main(): read activity on client, fd=<%d>\n", j->j_fd);
#endif
	  job_read(j);
	}
	if (job_iswork(j)) {	/* are we waiting for input and has it arrived ? */
	  job_do(j, set);
	  message_chain(set);

	}
	if (job_isend(j)) {	/* are we finished ? */
	  message_disconnect(set, j->j_pid, j->j_uid, j->j_gid);
	  smfd = j->j_fd;
	  job_end(j);
	  if (i < (set->s_jobcount - 1)) {
	    job_copy(j, &(set->s_jobs[set->s_jobcount - 1]));
	    i--;		/* WARNING: decrement so that copied job gets slice */
	  }
	  if (set->s_jobcount > 0) {
	    set->s_jobcount--;
	  }
	  if (smfd >= mfd) {	/* recompute mfd if we have a reason */

	    mfd = ltable[0];
	    for (t = 1; t < lc; t++) {
	      if (ltable[t] > mfd) {
		mfd = ltable[t];
	      }
	    }
	    for (t = 0; t < set->s_jobcount; t++) {
	      if (set->s_jobs[t].j_fd > mfd) {
		mfd = set->s_jobs[t].j_fd;
	      }
	    }
#ifdef TRACE
	    fprintf(stderr, "main(): reduced mfd from <%d> to <%d>\n", smfd, mfd);
#endif
	  }
	}			/* end of shutdown */
      }				/* end of handling connected sockets */

      /* WARNING: jobcount should never exceed jobmax */
      if (lc + set->s_jobcount >= set->s_jobmax) {
	/* drop those nonroot users which are over quota */
#ifdef TRACE
	fprintf(stderr, "main(): need to prune\n");
#endif
	prune(set);
      }

    }
    /* end of handling select */
  } while (run);

#ifdef TRACE
  fprintf(stderr, "main(): finished\n");
#endif

  /* delete listeners */
  for (i = 0; i < lc; i++) {
    close(ltable[i]);
  }
  free(ltable);
  ltable = NULL;
  lc = 0;

  message_stop(set, VERSION);

  /* delete state set */
  set_free(set);

  return 0;
}
