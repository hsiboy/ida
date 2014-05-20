#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "udomain.h"

/* lock listen socket */
static volatile int socklstn = (-1);
/* accepted connection */
static volatile int sockacpt = (-1);

static void socketdo(int s)
{
  int sl;
  struct sockaddr_un sa;

/*  fcntl (sockl, F_SETOWN, getpid()); */

  if (sockacpt >= 0) {
    close(sockacpt);
    sockacpt = (-1);
  }
  sl = sizeof(struct sockaddr_un);
  sockacpt = accept(socklstn, (struct sockaddr *) &sa, &sl);
}

int socketlock(char *name, int zap)
{
  mode_t mask;
  struct sigaction sag;
  int socklflags;
  int result = 0;

  mask = umask(S_IXUSR | S_IRWXO | S_IRWXG);

  /* accept connections to lock asynchronously, do accept in signal handler */
  sag.sa_handler = socketdo;
  sigfillset(&(sag.sa_mask));
  /* sigdelset(&(sag.sa_mask), SIGTERM); */
  sag.sa_flags = SA_RESTART;
  sigaction(SIGIO, &sag, NULL);

  socklstn = udomainlisten(name, 1, zap);
  if (socklstn < 0) {
    result++;
  } else {
    socklflags = fcntl(socklstn, F_GETFL, 0);
    fcntl(socklstn, F_SETFL, O_NONBLOCK | O_ASYNC | socklflags);
    fcntl(socklstn, F_SETOWN, getpid());
  }

  umask(mask);

  return result;
}
