#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include "misc.h"
#include "socketlock.h"
#include "sparse.h"

#define LOG_PORT           514	/* udp port to listen on */

#define LOG_LINE          1024	/* buffer / line length */

#define LOG_SCHEME       "rlog"
#define LOG_SERVICE      "rlog"

#define LOG_LOCK "/var/run/idsarlogd"

struct tacl {			/* list of allowed hosts */
  unsigned long int t_addr;
  char *t_name;
};

static volatile int run = 1;

static void handle(int s)
{
  run = 0;
}

int main(int argc, char **argv)
{
  int lfd;
  IDSA_CONNECTION *con;

  int rr;
  char buffer[LOG_LINE];

  struct sigaction sag;

  struct hostent *addrptr;
  struct sockaddr_in addr;
  int alen;

  struct tacl *hostable = NULL;
  struct tacl *ptable;
  struct tacl qtable;
  int tsize = 0;

  int i = 1, j = 1;

  int zap = 0;
  int logfrag = 0;
  int recvz = 0;
  int dolog = 0;
  char *id = NULL;
  char *rootdir = NULL;
  short logport = LOG_PORT;
  char *logaddr = NULL;
  IDSA_EVENT *evt;

#ifdef TRACE
  int nofork = 1;
#else
  int nofork = 0;
#endif

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("usage: %s [-fkln] [-b local address] [-d size] [-i user] [-p port] [-r directory] authorized host list\n", argv[0]);
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
      case 'd':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if ((i < argc) && (recvz = atoi(argv[i] + j))) {
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -d option requires a nonzero integer as argument\n", argv[0]);
	  exit(1);
	}
	break;
      case 'p':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if ((i < argc) && (logport = atoi(argv[i] + j))) {
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -p option requires a udp port number as argument\n", argv[0]);
	  exit(1);
	}
	break;
      case 'b':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  logaddr = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -b option requires an interface address as parameter\n", argv[0]);
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
      case 'f':
	logfrag++;
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
      case 'l':
	dolog++;
	j++;
	break;
      case 'v':
	printf("idsarlogd %s\n", VERSION);
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
      ptable = realloc(hostable, sizeof(struct tacl) * (tsize + 1));
      if (ptable) {

	if (inet_aton(argv[i], &(addr.sin_addr))) {	/* it was an IP */
	  ptable[tsize].t_addr = addr.sin_addr.s_addr;
	  addrptr = gethostbyaddr((char *) &(addr.sin_addr), sizeof(struct in_addr), AF_INET);
	  if (addrptr == NULL) {
	    fprintf(stderr, "%s: Can not reverse %s\n", argv[0], argv[i]);
	    ptable[tsize].t_name = strdup(argv[i]);
	  } else {
	    ptable[tsize].t_name = strdup(addrptr->h_name);
	  }
	} else {		/* user gave us a name */
	  ptable[tsize].t_name = strdup(argv[i]);
	  addrptr = gethostbyname(argv[i]);
	  if (addrptr == NULL) {
	    fprintf(stderr, "%s: Can not resolve %s\n", argv[0], argv[i]);
	    exit(1);
	  } else {
	    addr.sin_addr = *(struct in_addr *) addrptr->h_addr;
	    ptable[tsize].t_addr = addr.sin_addr.s_addr;
	  }
	}

	if (ptable[tsize].t_name == NULL) {
	  fprintf(stderr, "%s: Unable to copy string: %s\n", argv[0], strerror(errno));
	  exit(1);
	}
#ifdef TRACE
	fprintf(stderr, "main(): name <%s>, ip=<0x%08x>\n", ptable[tsize].t_name, (int) ptable[tsize].t_addr);
#endif
	tsize++;
	hostable = ptable;

	i++;
	j = 1;
      } else {
	fprintf(stderr, "%s: unable to allocate %d bytes: %s\n", argv[0], sizeof(struct tacl) * (tsize + 1), strerror(errno));
	exit(1);
      }
    }
  }

  if (hostable == NULL) {
    fprintf(stderr, "%s: require at least one host as parameter\n", argv[0]);
    exit(1);
  }

  sag.sa_handler = handle;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = 0;		/* TERM and ALRM are supposed to interrrupt us */
  sigaction(SIGTERM, &sag, NULL);

  if (nofork == 0) {
    fork_parent(argv[0]);
  }

  if (socketlock(LOG_LOCK, zap)) {
    fprintf(stderr, "%s: unable to acquire lock: %s\n", argv[0], strerror(errno));
    exit(1);
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(logport);
  if (logaddr) {
    if (inet_aton(logaddr, &(addr.sin_addr)) == 0) {
      addrptr = gethostbyname(logaddr);
      if (addrptr == NULL) {
	fprintf(stderr, "%s: could not resolve %s\n", argv[0], logaddr);
	exit(1);
      } else {
	if (addrptr->h_addrtype == AF_INET) {
	  addr.sin_addr = *(struct in_addr *) addrptr->h_addr;
	} else {
	  fprintf(stderr, "%s: can not deal with address type %d\n", argv[0], addrptr->h_addrtype);
	  exit(1);
	}
      }
    }
  } else {
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  if ((lfd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    fprintf(stderr, "%s: unable to open socket: %s\n", argv[0], strerror(errno));
    exit(1);
  }
  if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr))) {
    fprintf(stderr, "%s: unable to bind socket: %s\n", argv[0], strerror(errno));
    exit(1);
  }
  if (recvz) {
    if (setsockopt(lfd, SOL_SOCKET, SO_RCVBUF, &recvz, sizeof(int))) {
      fprintf(stderr, "%s: unable to set buffer to %d: %s\n", argv[0], recvz, strerror(errno));
      exit(1);
    }
  }

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

  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_SUCCESS, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTART, "version", IDSA_T_STRING, VERSION, NULL);

  while (run) {

    alen = sizeof(addr);
    rr = recvfrom(lfd, buffer, LOG_LINE, 0, (struct sockaddr *) &addr, &alen);
    if (rr > 0) {
      if (logfrag || (buffer[rr - 1] == '\n')) {
	buffer[rr - 1] = '\0';

#ifdef TRACE
	fprintf(stderr, "main(): tsize=%d, received <", tsize);
	for (i = 0; i < rr; i++)
	  fputc(buffer[i], stderr);
	fprintf(stderr, ">\n");
#endif

	/* if empty hostable, tsize == 0, loop never is run */
	for (i = 0; (i < tsize) && (addr.sin_addr.s_addr != hostable[i].t_addr); i++) {
#ifdef TRACE
	  fprintf(stderr, "main(): considering <%d:%s>\n", i, hostable[i].t_name);
#endif
	}

	if (i < tsize) {

#ifdef TRACE
	  fprintf(stderr, "main(): found match <%d:%s>\n", i, hostable[i].t_name);
#endif

	  evt = idsa_event(con);
	  if (evt) {
	    parse_event(evt, buffer);	/* message, possibly service and pid */
	    idsa_host(evt, hostable[i].t_name);
	    idsa_scheme(evt, LOG_SCHEME);
	    idsa_log(con, evt);
	  }

	  if (i > 0) {		/* caching trick, percolate active hosts up */
	    qtable.t_addr = hostable[i].t_addr;
	    qtable.t_name = hostable[i].t_name;

	    hostable[i].t_addr = hostable[i - 1].t_addr;
	    hostable[i].t_name = hostable[i - 1].t_name;

	    hostable[i - 1].t_addr = qtable.t_addr;
	    hostable[i - 1].t_name = qtable.t_name;
	  }
	}			/* else not in table */
      }				/* else broken fragment */
    }
  }

  /* FIXME: maybe write shutdown ? */
  idsa_set(con, "status", LOG_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_SSM, IDSA_T_STRING, IDSA_SSM_SSTOP, "version", IDSA_T_STRING, VERSION, NULL);

  if (hostable) {
    for (i = 0; i < tsize; i++) {
      free(hostable->t_name);
      hostable->t_name = NULL;
    }
    free(hostable);
    hostable = NULL;
  }
  close(lfd);
  idsa_close(con);

  return 0;
}
