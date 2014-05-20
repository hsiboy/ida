#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>

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

#define WRAPPER_SCHEME  "tcpd"
#define WRAPPER_SERVICE "tcpd"
#define WRAPPER_COMMENT   128

int main(int argc, char **argv)
{
  IDSA_CONNECTION *con;
  IDSA_EVENT *evt;
  int i, j;
  int offset;
  int result;
  char *service;
  struct sockaddr_in ca, sa;
  int salen, calen;
  int sp[2], cp[2];
  char comment[WRAPPER_COMMENT];
  int type, typelen;
  unsigned long int srcaddr, dstaddr;
  unsigned int arisk, crisk, irisk;
  char riskswitch;

  arisk = IDSA_R_SUCCESS;
  crisk = IDSA_R_UNKNOWN;
  irisk = IDSA_R_UNKNOWN;

  i = 0;
  j = 1;
  offset = argc;		/* WARNING: inetd does not obey normal exec conventions */
  service = NULL;

  con = idsa_open(WRAPPER_SERVICE, NULL, 0);

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 's':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  service = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, "-s requires a string as parameter", NULL);
	  exit(1);
	}
	break;
      case 'r':
	j++;
	if (argv[i][j] == '\0') {
	  idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, "-r[aci] <risk>", NULL);
	  exit(1);
	}
	riskswitch = argv[i][j];
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i >= argc) {
	  idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, "-r%c requires a risk parameter", NULL);
	  exit(1);
	}
	switch (riskswitch) {
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
	  idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, "-r%c not supported, use -ra, -rc or -ri", NULL);
	  break;
	}
	i++;
	j = 1;
	break;
      case '-':
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      default:
	snprintf(comment, WRAPPER_COMMENT, "unknown option -%c", argv[i][j]);
	comment[WRAPPER_COMMENT - 1] = '\0';
	idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, comment, NULL);
	exit(1);
	break;
      }
    } else {
#ifdef TRACE
      fprintf(stderr, "main(): found offset at %d\n", i);
#endif
      offset = i;
      i = argc;
    }
  }

  if (offset >= argc) {
    idsa_set(con, "error-usage", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "comment", IDSA_T_STRING, "nothing to run", NULL);
    exit(1);
  }
  if (service == NULL) {
    service = argv[offset];
    for (i = 0; argv[offset][i] != '\0'; i++) {
      if (argv[offset][i] == '/') {
	service = argv[offset] + i + 1;
      }
    }
  }
  if (service) {
    evt = idsa_event(con);
    if (evt) {
      idsa_service(evt, service);
      idsa_template(con, evt);
    }
  }
  sp[0] = IPPROTO_TCP;
  salen = sizeof(struct sockaddr_in);
  cp[0] = IPPROTO_TCP;
  calen = sizeof(struct sockaddr_in);

  typelen = sizeof(int);
  if ((getsockname(STDIN_FILENO, (struct sockaddr *) &sa, &salen) >= 0)
      && (getpeername(STDIN_FILENO, (struct sockaddr *) &ca, &calen) >= 0)
      && (getsockopt(STDIN_FILENO, SOL_SOCKET, SO_TYPE, &type, &typelen) >= 0)) {
    if ((sa.sin_family == AF_INET) && (type == SOCK_STREAM)) {
      sp[1] = ntohs(sa.sin_port);
      cp[1] = ntohs(ca.sin_port);
    } else {
      idsa_set(con, "error-unhandled", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_UNHANDLED, "comment", IDSA_T_STRING, "unsupported protcol", NULL);
      exit(1);
    }
  } else {
    idsa_set(con, "error-system", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, IDSA_ES_SYS_ERRNO, IDSA_T_ERRNO, &errno, "comment", IDSA_T_STRING, "unable to get address", NULL);
    if (isatty(STDERR_FILENO)) {
      fprintf(stderr, "%s: simple tcp wrapper replacement to be run by network superserver\n", argv[0]);
    }
    exit(1);
  }

  /* alternative 0: old approach */
  srcaddr = ntohl(ca.sin_addr.s_addr);
  dstaddr = ntohl(sa.sin_addr.s_addr);
  result = idsa_set(con, "connect", WRAPPER_SCHEME, 1, arisk, crisk, irisk, "ip4src", IDSA_T_IP4ADDR, &srcaddr, "portsrc", IDSA_T_IPPORT, cp, "ip4dst", IDSA_T_IP4ADDR, &dstaddr, "portdst", IDSA_T_IPPORT, sp, NULL);

  /* alternative 1: access control schema - also note the use of the simpler IDSA_T_SADDR instead of IP4ADDR and IPPORT */
  /* result = idsa_set(con, "connect", WRAPPER_SCHEME, 1, arisk, crisk, irisk, IDSA_AM_SUBJECT, IDSA_T_SADDR, &ca, IDSA_AM_OBJECT, IDSA_T_SADDR, &sa, IDSA_AM_ACTION, IDSA_T_STRING, IDSA_AM_AREQUEST, NULL); */

  /* alternative 2: logging data map http://www.ranum.com/logging/logging-data-map.html */
  /* result = idsa_set(con, "connect", WRAPPER_SCHEME, 1, arisk, crisk, irisk, IDSA_LDM_SRCDEV, IDSA_T_SADDR, &ca, IDSA_LDM_TARGDEV, IDSA_T_SADDR, &sa, NULL); */

  if (result == IDSA_L_ALLOW) {
    /* reset signal handler for client */
    signal(SIGPIPE, SIG_DFL);

#ifdef TRACE
    for (i = 0; i < argc; i++) {
      printf("argv[%d]=%s\n", i, argv[i]);
    }
    printf("offset=%d\n", offset);
    fflush(stdout);
#endif

    execvp(argv[offset], &(argv[offset]));

    snprintf(comment, WRAPPER_COMMENT, "unable to exec %s", argv[argc - offset]);
    comment[WRAPPER_COMMENT - 1] = '\0';
    idsa_set(con, "error-system", WRAPPER_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_NONE, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, IDSA_ES_SYS_ERRNO, IDSA_T_ERRNO, &errno, "comment", IDSA_T_STRING, comment, NULL);
    exit(1);
  }
  return 0;
}
