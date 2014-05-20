#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include "ucred.h"
#include "udomain.h"
#include "misc.h"
#include "sparse.h"

#ifdef _PATH_LOG
#define LOG_SOCKET _PATH_LOG
#else
#define LOG_SOCKET "/dev/log"
#endif

#define LOG_BACKLOG         32	/* number of connections pending in listen */
#define LOG_LINE          1024	/* buffer / line length */
#define LOG_OFFSET          20	/* starting point of search for service name */
#define LOG_TABLE           16	/* minimum number of clients */
#define LOG_DROP             8	/* quota for nonroot users */

#define LOG_SCHEME     "syslog"
#define LOG_SERVICE    "syslog"

struct tentry {			/* table for connections */
  int t_fd;
  IDSA_UCRED t_ucred;
  char *t_buffer;
  int t_have;
};

static volatile int run = 1;

static void handle(int s)
{
  run = 0;
}

static void writelog(IDSA_CONNECTION * con, IDSA_UCRED * cred, char *str)
{
  IDSA_EVENT *evt;
  evt = idsa_event(con);
  if (evt) {
    parse_event(evt, str);
    idsa_uid(evt, cred->uid);
    idsa_gid(evt, cred->gid);
    idsa_pid(evt, cred->pid);
    idsa_scheme(evt, LOG_SCHEME);
    idsa_log(con, evt);
  }
}

int main(int argc, char **argv)
{
  fd_set fsr;
  int lfd, mfd, afd;
  IDSA_CONNECTION *con;
  struct tentry *tab;
  int sr, rr;
  struct sockaddr_un sa;
  int salen, crlen;
  char buffer[LOG_LINE];
  char *ptr;
  mode_t mask;
  struct sigaction sag;

  int dropworst;
  int dropthis;
  int dropuid;

  uid_t uidmax = 0;
  uid_t uidthis = 0;
  uid_t uidnext = 0;

  int i = 1, j = 1, k = 0;

#ifdef TRACE
  int nofork = 1;		/* don't go into background */
#else
  int nofork = 0;
#endif

  int zap = 0;			/* kill already running job */
  int dolog = 0;		/* log failures */
  char *id = NULL;
  char *rootdir = NULL;
  char *logsocket = NULL;

  int tabmax = 0;
  int tabhave = 0;

  tabmax = getdtablesize() - 8;
  if (tabmax < LOG_TABLE) {
    tabmax = LOG_TABLE;
  }

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("usage: %s [-kln] [-i user] [-m connection table size] [-r directory] [-p unix socket]\n", argv[0]);
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
      case 'm':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  tabmax = atoi(argv[i] + j);
	  if (tabmax <= 0) {
	    fprintf(stderr, "%s: -m requires a number greater than zero\n", argv[0]);
	    exit(1);
	  }
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -m option requires a number as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'p':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  logsocket = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -p option requires a unix domain socket as parameter\n", argv[0]);
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
      case 'k':
	zap++;
	j++;
	break;
      case 'n':
	nofork++;
	j++;
	break;
      case 'l':
	dolog++;
	j++;
	break;
      case 'v':
	printf("idsasyslogd %s\n", VERSION);
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
      fprintf(stderr, "%s: unknown parameter %s\n", argv[0], argv[i]);
      exit(1);
    }
  }

  sag.sa_handler = handle;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = 0;
  sigaction(SIGTERM, &sag, NULL);

  if (nofork == 0) {
    fork_parent(argv[0]);
  }

  tab = malloc(sizeof(struct tentry) * tabmax);
  if (tab == NULL) {
    fprintf(stderr, "%s: unable to allocate memory: %s\n", argv[0], strerror(errno));
    exit(1);
  }
  mask = umask(S_IXUSR | S_IXGRP | S_IXOTH | S_IRGRP | S_IROTH);
  lfd = udomainlisten(logsocket ? logsocket : LOG_SOCKET, LOG_BACKLOG, zap);
  if (lfd == (-1)) {
    fprintf(stderr, "%s: unable to listen on socket: %s\n", argv[0], strerror(errno));
    exit(1);
  }
  umask(mask);

  con = idsa_open(LOG_SERVICE, NULL, IDSA_F_ENV);
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

  mfd = 0;
  buffer[LOG_LINE - 1] = '\0';

  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_SUCCESS, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTART, "version", IDSA_T_STRING, VERSION, NULL);

  while (run) {

#ifdef TRACE
    fprintf(stderr, "main(): have 1+%d/%d file descriptors, max+1=%d\n", tabhave, tabmax, mfd);
#endif

    FD_ZERO(&fsr);
    FD_SET(lfd, &fsr);
#ifdef TRACE
    fprintf(stderr, "main(): table=%d, mfd=%d ", tabhave, mfd);
#endif
    for (i = 0; i < tabhave; i++) {
#ifdef TRACE
      fprintf(stderr, "[%d]=%d ", i, tab[i].t_fd);
#endif
      FD_SET(tab[i].t_fd, &fsr);
    }
#ifdef TRACE
    fprintf(stderr, "\n");
#endif
    if (mfd == 0) {		/* mfd out of sync, recompute */
      mfd = lfd;
      for (i = 0; i < tabhave; i++) {
	if (tab[i].t_fd >= mfd) {
	  mfd = tab[i].t_fd;
	}
      }
      mfd++;
#ifdef TRACE
      fprintf(stderr, "main(): mfd stale, recomputed to %d\n", mfd);
#endif
    }

    sr = select(mfd, &fsr, NULL, NULL, NULL);
    if (sr > 0) {
      if (FD_ISSET(lfd, &fsr)) {	/* handle new connection */

/****** Check if we are out of table space and have nonroot users ***********/

	if ((tabhave >= tabmax) && (uidmax > 0)) {

	  dropworst = 0;
	  dropuid = uidmax;

	  /* WARNING: This looks like N^2 but */
	  /* generally is 2*N, root and the attacker. Outer while */
	  /* loop iterates over each client uid, inner over all */
	  /* connections for a given uid */

	  while (uidthis > 0) {	/* look through all uids for victim dropuid */
	    uidnext = 0;
	    dropthis = 0;
	    for (i = 0; i < tabhave; i++) {
	      if (uidthis == tab[i].t_ucred.uid) {	/* count same uids */
		dropthis++;
		j = i;
	      } else if ((uidthis > tab[i].t_ucred.uid) && (uidnext < tab[i].t_ucred.uid)) {
		uidnext = tab[i].t_ucred.uid;
	      }
	    }
	    if (dropworst < dropthis) {	/* update best */
	      dropworst = dropthis;
	      dropuid = uidthis;
	    } else if ((dropthis == 0) && (uidthis == uidmax)) {
	      uidmax = uidnext;
	    }
	    uidthis = uidnext;	/* move onto next uid */
	  }

#ifdef TRACE
	  fprintf(stderr, "main(): about to shut down %u with %d instances\n", dropuid, dropworst);
#endif

	  i = 0;
	  while (i < tabhave) {	/* close all instances of dropuid */
	    if (tab[i].t_ucred.uid == dropuid) {
	      mfd = 0;
	      close(tab[i].t_fd);
	      if (tab[i].t_buffer) {
		free(tab[i].t_buffer);
		tab[i].t_buffer = NULL;
	      }
#ifdef TRACE
	      fprintf(stderr, "main(): closed %d/%d\n", i, tabhave);
#endif
	      tabhave--;
	      if (i < tabhave) {
		memcpy(&(tab[i]), &(tab[tabhave]), sizeof(struct tentry));
	      }
	    } else {
	      i++;
	    }
	  }
	}


	/* end of checking if we can drop something */
 /****** Insert new client into table if possible ****************************/
	if (tabhave < tabmax) {	/* enough space to accept new connection */
	  salen = sizeof(sizeof(struct sockaddr_un));
	  afd = accept(lfd, (struct sockaddr *) &sa, &salen);
	  if (afd >= 0) {
	    tab[tabhave].t_fd = afd;
	    tab[tabhave].t_buffer = NULL;
	    tab[tabhave].t_have = 0;

#ifdef SO_PEERCRED
	    crlen = sizeof(IDSA_UCRED);
	    if (getsockopt(afd, SOL_SOCKET, SO_PEERCRED, &(tab[tabhave].t_ucred), &crlen) == 0) {
#ifdef TRACE
	      fprintf(stderr, "main(): accepted fd=%d, pid=%d, uid=%d, table=%d\n", afd, tab[tabhave].t_ucred.pid, tab[tabhave].t_ucred.uid, tabhave);
#endif
	      if (tab[tabhave].t_ucred.uid > uidmax) {
		uidmax = tab[tabhave].t_ucred.uid;
	      }
	      tabhave++;
	      if ((afd >= mfd) && (mfd != 0)) {
		mfd = afd + 1;
	      }
	    } else {
	      /* FIXME: report failure */
	      close(afd);
	    }
#else
	    tab[tabhave].t_ucred.uid = (-1);
	    tab[tabhave].t_ucred.gid = (-1);
	    tab[tabhave].t_ucred.pid = 0;
#endif
	  }			/* else probably not worth reporting accept failures */
	}			/* else report limit */
	sr--;
      }
      /* end of handling new connections */

/**** Handle existing connections *******************************************/
      i = 0;
      while ((sr > 0) && (i < tabhave)) {
	if (FD_ISSET(tab[i].t_fd, &fsr)) {	/* this connection wants to be read */
	  if (tab[i].t_buffer) {	/* append to saved fragment */
	    rr = read(tab[i].t_fd, tab[i].t_buffer + tab[i].t_have, LOG_LINE - (1 + tab[i].t_have));
	    ptr = tab[i].t_buffer;
	    if (rr > 0) {
	      rr += tab[i].t_have;	/* add in any previous fragments */
	    }
	  } else {		/* use single shared buffer */
	    rr = read(tab[i].t_fd, buffer, LOG_LINE - 1);
	    ptr = buffer;
	  }

	  if (rr > 0) {		/* success */
	    ptr[rr] = '\0';	/* safe, we only read in LOG_LINE-1 */
	    k = 0;

	    do {
	      /* chop out initial nulls */
	      for (; (k < rr) && (ptr[k] == '\0'); k++);

	      /* look for end of message */
	      for (j = k; (j < rr) && (ptr[j] != '\0'); j++);

	      /* now j>0 || j==r */

	      if (j < rr) {	/* found a complete message */
#ifdef TRACE
		fprintf(stderr, "main([%d]=%d): complete message between %d,%d\n", i, tab[i].t_fd, k, j);
#endif
		if ((j > 0) && (ptr[j - 1] == '\n')) {	/* turf extra \n */
		  ptr[j - 1] = '\0';
		}

		writelog(con, &(tab[i].t_ucred), ptr + k);

		k = j + 1;

	      }
	    } while (j < rr);	/* another full message can be written */

/********** Deal with incomplete fragments **********************************/

	    if (k < rr) {	/* last message incomplete, better save it */
	      if (tab[i].t_buffer == NULL) {	/* need to allocate save buffer */
#ifdef TRACE
		fprintf(stderr, "main(%d): need to save fragment between %d,%d in new buffer\n", i, k, rr);
#endif
		tab[i].t_buffer = malloc(sizeof(char) * LOG_LINE);
		if (tab[i].t_buffer) {
		  memcpy(tab[i].t_buffer, ptr + k, rr - k);
		  tab[i].t_buffer[LOG_LINE - 1] = '\0';
		  tab[i].t_have = rr - k;
		} else {
		  tab[i].t_have = 0;
		  /* FIXME: report malloc failure */
		}
	      } else {		/* already have buffer, do we need to move ? */
		if (k == 0) {	/* no change, check if message too long */
		  if (rr >= (LOG_LINE - 1)) {	/* message too long */
		    tab[i].t_buffer[LOG_LINE - 1] = '\0';
		    writelog(con, &(tab[i].t_ucred), tab[i].t_buffer);
		    /* FIXME: could mention oversize */

#ifdef TRACE
		    fprintf(stderr, "main(%d): need to destroy large fragment between %d,%d in buffer\n", i, k, rr);
#endif
		    free(tab[i].t_buffer);
		    tab[i].t_buffer = NULL;
		    tab[i].t_have = 0;
		  } else {
#ifdef TRACE
		    fprintf(stderr, "main(%d): need to save fragment between %d,%d in unchanged buffer\n", i, k, rr);
#endif
		    tab[i].t_have = rr;
		  }
		} else {
#ifdef TRACE
		  fprintf(stderr, "main(%d): need to save fragment between %d,%d in moved buffer\n", i, k, rr);
#endif
		  memmove(tab[i].t_buffer, ptr + k, rr - k);
		  tab[i].t_have = rr - k;
		}
	      }
	    } else {		/* free buffer if we had one */
#ifdef TRACE
	      fprintf(stderr, "main(%d): write complete with %d\n", i, rr);
#endif
	      if (tab[i].t_buffer) {
		free(tab[i].t_buffer);
		tab[i].t_buffer = NULL;
	      }
	      tab[i].t_have = 0;
	    }

	    i++;
	  } else {
/********** Deal with failed reads ******************************************/
	    if ((rr < 0) && (errno == EINTR)) {	/* tolerable failure */
	      i++;
	    } else {		/* eof or serious failure: close connection */
#ifdef TRACE
	      fprintf(stderr, "main(): deleting entry=%d, fd=%d\n", i, tab[i].t_fd);
#endif
	      mfd = 0;		/* out of sync */
	      close(tab[i].t_fd);
	      if (tab[i].t_buffer) {
		writelog(con, &(tab[i].t_ucred), tab[i].t_buffer);
		/* FIXME : could mention incomplete */
		free(tab[i].t_buffer);
		tab[i].t_buffer = NULL;
	      }
	      tabhave--;
	      if (i < tabhave) {
		memcpy(&(tab[i]), &(tab[tabhave]), sizeof(struct tentry));
	      }
	    }
	  }
	  sr--;
	} else {
/******** Deal with idle connection *****************************************/
	  i++;
	}
      }
    }
  }

  close(lfd);
  for (i = 0; i < tabhave; i++) {
    close(tab[i].t_fd);
    if (tab[i].t_buffer) {
      writelog(con, &(tab[i].t_ucred), tab[i].t_buffer);
      /* FIXME: could mention incomplete */
      free(tab[i].t_buffer);
      tab[i].t_buffer = NULL;
    }
    tab[i].t_have = 0;
  }
  free(tab);

  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTOP, "version", IDSA_T_STRING, VERSION, NULL);
  idsa_close(con);

  return 0;
}
