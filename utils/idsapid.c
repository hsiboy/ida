#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sched.h>

#include <sys/types.h>

#include <idsa_internal.h>

#include "udomain.h"

#define PID_TIMEOUT 2

int main(int argc, char **argv)
{
  int i = 1, j = 1;
  pid_t pid;

  int zap = 0;
  int done = 0;

  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	exit(0);
	break;
      case 'h':
	printf("usage: idsapid [-k] [unix socket ...]\n");
	exit(0);
	break;
      case '-':
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      case 'k':
	zap = SIGTERM;
	j++;
	break;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
	zap = atoi(argv[i] + j);
	j++;
	break;
      default:
	fprintf(stderr, "%s: unknown option -%c\n", argv[0], argv[i][j]);
	exit(1);
	break;
      }
    } else {
      alarm(PID_TIMEOUT);
      pid = udomainowner(argv[i]);
      if (pid > 0) {
	if (zap) {
	  /* could there be a kernel bug ? in socketlock I block all other
	     signals during IO done in handler, but SIGTERM is set to interrupt
	     syscalls - still the kill sometimes doesn't take */
	  sched_yield();
	  kill(pid, zap);
	} else {
	  printf("%d\n", pid);
	}
      } else {
	if (pid < 0) {
	  fprintf(stderr, "%s: unable to establish owner of %s: %s\n", argv[0], argv[i], strerror(errno));
	}
      }
      done++;
      i++;
    }
  }

  if (done == 0) {
    if (zap) {
      fprintf(stderr, "%s: need to specify socket explictly for kill\n", argv[0]);
      exit(1);
    }
    alarm(PID_TIMEOUT);
    pid = udomainowner(IDSA_SOCKET);
    if (pid > 0) {
      printf("%d\n", pid);
    } else {
      if (pid < 0) {
	fprintf(stderr, "%s: unable to establish owner of %s: %s\n", argv[0], IDSA_SOCKET, strerror(errno));
      }
    }
  }
  return 0;
}
