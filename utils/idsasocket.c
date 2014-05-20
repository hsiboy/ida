#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFFER 1024

#include <udomain.h>

volatile int ioready = 0;
int debug = 0;

void handler(int s)
{
  ioready = 1;
}

void printdebug(unsigned char *b, int l, char m)
{
  int i, j;
  static int w = 0;
  char *p;

  if (w == 0) {
    p = getenv("COLUMNS");
    if (p) {
      w = atoi(p);
    }
    if (w <= 0) {
      w = 65;
    }
  }

  fputc(m, stderr);
  for (i = 0; i < (w / 5 * 4) + 2; i++) {
    fputc('-', stderr);
  }
  fputc('\n', stderr);
  i = 0;
  while (i < l) {
    fputc(m, stderr);
    for (j = 0; (j < w / 5); j++) {
      if (i + j < l) {
	fprintf(stderr, "%02x ", b[i + j]);
      } else {
	fprintf(stderr, "   ");
      }
    }
    fprintf(stderr, "  ");
    for (j = 0; (j < w / 5) && (i + j < l); j++) {
      if (isprint(b[i + j])) {
	fputc(b[i + j], stderr);
      } else {
	fputc('.', stderr);
      }
    }
    fputc('\n', stderr);
    i += j;
  }
}

void copy(char *s, int fd)
{
  char buffer[BUFFER];
  int rr, wr;

  ioready = 0;

  rr = read(fd, buffer, BUFFER);
  switch (rr) {
  case -1:
    switch (errno) {
    case EAGAIN:
    case EINTR:
      break;
    default:
      fprintf(stderr, "%s: read error: %s\n", s, strerror(errno));
      exit(1);
      break;
    }
    break;
  case 0:
    exit(0);
    break;
  default:
    if (debug)
      printdebug(buffer, rr, '>');
    ioready = 1;
    wr = write(STDOUT_FILENO, buffer, rr);
    if (wr < rr) {
      fprintf(stderr, "%s: incomplete write\n", s);
      exit(1);
    }
    break;
  }

  rr = read(STDIN_FILENO, buffer, BUFFER);
  switch (rr) {
  case -1:
    switch (errno) {
    case EAGAIN:
    case EINTR:
      break;
    default:
      fprintf(stderr, "%s: read error: %s\n", s, strerror(errno));
      exit(1);
      break;
    }
    break;
  case 0:
    exit(0);
    break;
  default:
    if (debug)
      printdebug(buffer, rr, '<');
    ioready = 1;
    wr = write(fd, buffer, rr);
    if (wr < rr) {
      fprintf(stderr, "%s: incomplete write\n", s);
      exit(1);
    }
    break;
  }


  if (ioready == 0) {
    pause();
  }

}

int makeasync(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, O_NONBLOCK | O_ASYNC | flags);
  fcntl(fd, F_SETOWN, getpid());

  return 0;
}

int main(int argc, char **argv)
{
  int server = 0;
  int respond = 1;

  int i, j, fd, nfd;
  char *name;

  int sl;
  struct sockaddr_un sa;

  struct sigaction sag;

  name = NULL;
  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("Usage: %s [-d] [-b] [-B] socket\n", argv[0]);
	exit(0);
	break;
      case 'B':
	server = 1;
	respond = 0;
	j++;
	break;
      case 'b':
	server = 1;
	j++;
	break;
      case 'd':
	debug++;
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
	exit(2);
	break;
      }
    } else {
      name = argv[i];
      i = argc;
    }
  }

  if (name == NULL) {
    fprintf(stderr, "%s: require a unix domain socket as argument\n", argv[0]);
    exit(1);
  }

  sag.sa_handler = handler;
  sigfillset(&(sag.sa_mask));
  sag.sa_flags = SA_RESTART;
  sigaction(SIGIO, &sag, NULL);

  makeasync(STDIN_FILENO);
  makeasync(STDOUT_FILENO);

  if (server) {
    fd = udomainlisten(name, 5, 0);

    if (fd < 0) {
      fprintf(stderr, "%s: unable to listen on %s: %s\n", argv[0], name, strerror(errno));
      exit(1);
    }

    if (respond) {

      sl = sizeof(struct sockaddr_un);
      nfd = accept(fd, (struct sockaddr *) &sa, &sl);
      close(fd);
      if (nfd < 0) {
	fprintf(stderr, "%s: unable to accept from %s: %s\n", argv[0], name, strerror(errno));
	exit(1);
      }

      makeasync(nfd);

      while (1) {
	copy(argv[0], nfd);
      }

    } else {
      pause();
    }
  } else {
    fd = udomainconnect(name);

    if (fd < 0) {
      fprintf(stderr, "%s: unable to connect to %s: %s\n", argv[0], name, strerror(errno));
      exit(1);
    }

    makeasync(fd);

    while (1) {
      copy(argv[0], fd);
    }

  }

  return 0;
}
