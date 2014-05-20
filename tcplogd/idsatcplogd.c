/****************************************************************************/
/*                                                                          */
/* Very simple TCP logger.                                                  */
/*                                                                          */
/****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#if (!defined(__linux__)) || ((defined(__GLIBC__) && (__GLIBC__ >= 2)))
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#else
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#endif

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include "misc.h"
#include "udomain.h"
#include "socketlock.h"

/* lock socket */
#define TCPLOG_LOCK    "/var/run/idsatcplogd"

/* largest IHL is 0b1111*4=60 */
#define TCPLOG_MAX     (60+sizeof(struct tcphdr))
#define TCPLOG_MIN     (sizeof(struct iphdr)+sizeof(struct tcphdr))

/* bitmap size for an unsigned short: 2^16 bits = 2^13 bytes */
#define TCPLOG_BITMAP  8192

/* low ports */
#define TCPLOG_RESERVED 1024

#define TCPLOG_SERVICE  "tcplog"
#define TCPLOG_SCHEME   "tcplog"

/* signal number */
volatile int signum = 0;

int main(int argc, char **argv)
{
  IDSA_CONNECTION *con;
  IDSA_EVENT *evt;
  int i, j, k;

#ifdef TRACE
  int nofork = 1;
#else
  int nofork = 0;
#endif
  int run = 1;
  int zap = 0;
  char *id = NULL;
  char *rootdir = NULL;
  int fd;
  int srcport[2], dstport[2];

  int true, false;

  struct iphdr *ipptr;
  struct tcphdr *tcpptr;
  unsigned char buffer[TCPLOG_MAX];
  unsigned char bitmap[TCPLOG_BITMAP];
  unsigned short offset;
  unsigned long int srcaddr, dstaddr;

  true = 1;
  false = 0;

  for (i = 0; i < TCPLOG_BITMAP; i++) {
    bitmap[i] = 0x00;
  }
  i = 1;
  j = 1;

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'A':
	for (k = 1; k < TCPLOG_RESERVED; k++) {
	  if (test_port(k) == 0) {	/* port not connected */
	    bitmap[k / 8] = (bitmap[k / 8]) | (1 << (k % 8));
	  }
	}
	j++;
	break;
      case 'a':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	while ((i < argc) && (argv[i][j] != '-')) {
	  k = atoi(argv[i] + j);
	  if (k) {
	    bitmap[k / 8] = (bitmap[k / 8]) | (1 << (k % 8));
	  } else {
	    fprintf(stderr, "%s: -a option requires at least one nonzero port number\n", argv[0]);
	    exit(1);
	  }
	  j = 0;
	  i++;
	}

	break;
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("%s: very simple tcp log daemon\n", argv[0]);
	printf("usage: %s [-Akn] [-a port ...] [-i user] [-r directory]\n", argv[0]);
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
      case 'k':
	zap++;
	j++;
	break;
      case 'n':
	nofork++;
	j++;
	break;
      case 'v':
	printf("idsatcplogd %s\n", VERSION);
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

  if (nofork == 0) {
    /* stderr is now a pipe, parent waits for close */
    fork_parent(argv[0]);
  }

  srcport[0] = IPPROTO_TCP;
  dstport[0] = IPPROTO_TCP;

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (fd < 0) {
    fprintf(stderr, "%s: unable to open socket in raw mode: %s\n", argv[0], strerror(errno));
    exit(1);
  }
  if (socketlock(TCPLOG_LOCK, zap)) {
    fprintf(stderr, "%s: unable to set up lock socket %s: %s\n", argv[0], TCPLOG_LOCK, strerror(errno));
    exit(1);
  }

  con = idsa_open(TCPLOG_SERVICE, NULL, IDSA_F_ENV | IDSA_F_UPLOAD);
  if (con == NULL) {
    fprintf(stderr, "%s: unable to connect to idsad\n", argv[0]);
    exit(1);
  }

  drop_root(argv[0], id, rootdir);
  drop_fork(argv[0]);

  evt = idsa_event(con);
  if (evt) {
    idsa_name(evt, "packet");
    idsa_scheme(evt, TCPLOG_SCHEME);
    /* FIXME: risks */
    idsa_template(con, evt);
  }

  if (nofork == 0) {
    fflush(stderr);
    fclose(stderr);
    close(STDERR_FILENO);
  }

  ipptr = (struct iphdr *) buffer;

  run = 1;
  while (run) {
    evt = idsa_event(con);
    if (evt) {
#ifdef TRACE
#endif
      if (read(fd, buffer, TCPLOG_MAX) >= TCPLOG_MIN) {
	offset = ((ipptr->ihl) << 2);
	tcpptr = (struct tcphdr *) (buffer + offset);

#ifdef TRACE
	fprintf(stderr, "main(): ihl=%d, offset=%d, buffer=%d, ipptr=%p, tcpptr=%p\n", ipptr->ihl, offset, TCPLOG_MAX, ipptr, tcpptr);
#endif

	srcport[1] = ntohs(tcpptr->source);
	dstport[1] = ntohs(tcpptr->dest);

#ifdef TRACE
	fprintf(stderr, "main(): dstport[1]=%d, dstport/8=%d, 1<<dstport%%8=%d\n", dstport[1], dstport[1] / 8, dstport[1] % 8);
#endif


	if (((tcpptr->syn == 1) && (tcpptr->ack == 0)) ||	/* new connection */
	    ((bitmap[dstport[1] / 8]) & (1 << (dstport[1] % 8)))) {	/* log everything */

	  srcaddr = ntohl(ipptr->saddr);
	  dstaddr = ntohl(ipptr->daddr);

	  idsa_add_set(evt, "ip4src", IDSA_T_ADDR, &srcaddr);
	  idsa_add_set(evt, "portsrc", IDSA_T_PORT, srcport);

	  idsa_add_set(evt, "ip4dst", IDSA_T_ADDR, &dstaddr);
	  idsa_add_set(evt, "portdst", IDSA_T_PORT, dstport);

	  idsa_add_integer(evt, "ip4ihl", ipptr->ihl);
	  idsa_add_integer(evt, "ip4tos", ipptr->tos);
	  idsa_add_integer(evt, "ip4ttl", ipptr->ttl);

	  idsa_add_set(evt, "tcpfin", IDSA_T_FLAG, (tcpptr->fin) ? &true : &false);
	  idsa_add_set(evt, "tcpsyn", IDSA_T_FLAG, (tcpptr->syn) ? &true : &false);
	  idsa_add_set(evt, "tcprst", IDSA_T_FLAG, (tcpptr->rst) ? &true : &false);
	  idsa_add_set(evt, "tcppsh", IDSA_T_FLAG, (tcpptr->psh) ? &true : &false);
	  idsa_add_set(evt, "tcpack", IDSA_T_FLAG, (tcpptr->ack) ? &true : &false);
	  idsa_add_set(evt, "tcpurg", IDSA_T_FLAG, (tcpptr->urg) ? &true : &false);

	  idsa_add_integer(evt, "tcpres2", tcpptr->res2);

#ifdef TRACE
	  idsa_event_dump(evt, stderr);
	  fprintf(stderr, "main(): ttl=%d, tos=%d, dest=%d\n", ipptr->ttl, ipptr->tos, tcpptr->dest);
#endif
	  idsa_log(con, evt);
	} else {		/* ignore this packet */
	  idsa_free(con, evt);
	}
      } else {
	idsa_risks(evt, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE);
	if (errno) {
	  i = errno;
	  idsa_add_string(evt, IDSA_ES, IDSA_ES_SYSTEM);
	  idsa_add_set(evt, IDSA_ES_SYS_ERRNO, IDSA_T_ERRNO, &i);
	} else {
	  idsa_add_string(evt, IDSA_ES, IDSA_ES_PROTOCOL);
	}
	idsa_name(evt, "error-read");
	idsa_log(con, evt);
	run = 0;
      }
    } else {
      run = 0;
    }
  }

  close(fd);
  idsa_close(con);

  return 0;
}
