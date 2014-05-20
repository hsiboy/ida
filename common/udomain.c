#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include "ucred.h"
#include "udomain.h"

/****************************************************************************/
/* Does       : Fancy atomic locking routine (assuming that .lock file does */
/*              not stick around)                                           */
/* Parameters : s - socket name, b - backlog, z - zap: terminate existing   */
/*              process                                                     */
/* Returns    : -1 on failure (locked, etc), fd on success                  */

int udomainlisten(char *s, int b, int z)
{
  int result;
  struct sockaddr_un sa;
  pid_t p;
  char t[sizeof(sa.sun_path)];

  /* build lockfile name */
  if (snprintf(t, sizeof(sa.sun_path) - 1, "%s.lock", s) >= sizeof(sa.sun_path)) {
    return -1;
  }
  t[sizeof(sa.sun_path) - 1] = '\0';

  result = socket(AF_UNIX, SOCK_STREAM, 0);
  if (result < 0) {
    return -1;
  }
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, t, sizeof(sa.sun_path));

  /* attempt to create lock socket */
  if (bind(result, (struct sockaddr *) &sa, sizeof(sa))) {
    /* fail - somebody else is already holding lock file */
    close(result);
    result = (-1);
  }
  if (listen(result, b)) {
    unlink(t);
    close(result);
    return -1;
  }
  /* try and get pid if there is a running process */
  p = udomainowner(s);

  if ((p > 0) && (!z)) {	/* if something running and we can't kill it give up */
    errno = EADDRINUSE;
    unlink(t);
    close(result);
    return -1;
  }

  if (rename(t, s)) {
    /* The code below is to cope with the no-rename braindamage of devfs */
    unlink(t);
    close(result);

    result = socket(AF_UNIX, SOCK_STREAM, 0);
    if (result < 0) {
      return -1;
    }
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, s, sizeof(sa.sun_path));

    unlink(s);

    /* attempt to create socket */
    if (bind(result, (struct sockaddr *) &sa, sizeof(sa))) {
      close(result);
      result = (-1);
    }
    if (listen(result, b)) {
      unlink(s);
      close(result);
      return -1;
    }
  }

  if ((p > 0) && (z)) {		/* if something running and we are authorized zap it */
    kill(p, SIGTERM);
  }

  /* make it close on exec */
  fcntl(result, F_SETFD, FD_CLOEXEC);

  return result;
}

int udomainconnect(char *s)
{
  int fd;
  struct sockaddr_un sa;

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, s, sizeof(sa.sun_path));

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd >= 0) {
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
      close(fd);
      fd = (-1);
    }
  } else {
    fd = (-1);
  }

  return fd;
}

pid_t udomainowner(char *s)
{
#ifdef SO_PEERCRED
  int fd;
  pid_t result;
  struct sockaddr_un sa;
  IDSA_UCRED cr;
  int cl;

  result = 0;
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, s, sizeof(sa.sun_path));

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd != (-1)) {
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) == 0) {
      cl = sizeof(IDSA_UCRED);
      if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) {
	result = cr.pid;
      } else {
	result = (-1);
      }
    } else {
      switch (errno) {
      case ECONNREFUSED:
	/* nothing there - but that is ok */
	result = 0;
	break;
      default:
	result = (-1);
	break;
      }
    }
    close(fd);
  } else {
    result = (-1);
  }
  return result;
#else
  fprintf(stderr, "idsa: WARNING: SO_PEERCRED not available\n");
  return -1;
#endif
}
