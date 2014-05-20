#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>

#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "misc.h"

/****************************************************************************/
/* Does       : check if a local port is connected                          */
/* Parameters : p - port number in host format                              */
/* Returns    : greater than zero if connected, zero if not, negative on    */
/*              failure                                                     */
/* Notes      : could be done in /proc/net/tcp - would be more quiet but    */
/*              also more fragile                                           */

int test_port(unsigned short p)
{
  int fd;
  struct sockaddr_in addr;
  int addrlen;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(p);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addrlen = sizeof(addr);

  fd = socket(AF_INET, SOCK_STREAM, 0);

  if (fd < 0) {
    return -1;
  }
  if (connect(fd, (struct sockaddr *) &(addr), addrlen)) {
    close(fd);
    if (errno == ECONNREFUSED) {
      return 0;
    } else {
      return -1;
    }
  } else {			/* local port is available */
    close(fd);
    return 1;
  }

}

/****************************************************************************/
/* Does       : system() replacement without involving a shell              */
/* Parameters : s - string to be executed                                   */

int strexec(char *s)
{
  int i, j, e;
  char **a;

  i = 0;
  j = 1;
  e = 0;
  while (s[i] != '\0') {
    if (isspace(s[i])) {
      j = 1;
    } else {
      if (j) {
	e++;
	j = 0;
      }
    }
    i++;
  }
#ifdef TRACE
  fprintf(stderr, "strexec(): <%s> has %d elements\n", s, e);
#endif
  e++;

  a = malloc(sizeof(char *) * e);
  if (a) {
    i = 0;
    j = 1;
    e = 0;
    while (s[i] != '\0') {
      if (isspace(s[i])) {
	s[i] = '\0';
	j = 1;
      } else {
	if (j) {
	  a[e] = s + i;
	  e++;
	  j = 0;
	}
      }
      i++;
    }
    a[e] = NULL;
    execvp(s, a);
#ifdef TRACE
    fprintf(stderr, "strexec(): execvp(%s,...) failed: %s\n", s, strerror(errno));
#endif
  }
  return -1;
}

#define TMP_BUFFER 256

void fork_parent(char *name)
{
  int p[2];
  pid_t pid;
  char buffer[TMP_BUFFER];
  int bl, kfd, maxfd;
  int rr, status, result;

  if (pipe(p)) {
    fprintf(stderr, "%s: unable to create pipe: %s\n", name, strerror(errno));
    exit(1);
  }

  fflush(stderr);

  pid = fork();
  switch (pid) {
  case -1:
    fprintf(stderr, "%s: unable to fork: %s\n", name, strerror(errno));
    exit(1);
    break;
  case 0:			/* in child - make pipe stderr and detach from terminal */
    close(p[0]);
    if (p[1] != STDERR_FILENO) {
      if (dup2(p[1], STDERR_FILENO) != STDERR_FILENO) {
	bl = snprintf(buffer, TMP_BUFFER, "%s: unable to dup2 stderr file descriptor: %s\n", name, strerror(errno));
	/* ouch */
	if ((bl > 0) && (bl < TMP_BUFFER)) {
	  write(p[1], buffer, bl);
	}
	exit(1);
      }
      close(p[1]);
    }
    close(STDOUT_FILENO);
    close(STDIN_FILENO);

    /* ugly, double edged sword */
    maxfd = getdtablesize();
    for (kfd = STDERR_FILENO + 1; kfd < maxfd; kfd++) {
      close(kfd);
    }

    setsid();
    break;
  default:			/* in parent - read from pipe, exit when pipe closes */
    close(p[1]);

    do {
      rr = read(p[0], buffer, TMP_BUFFER);
      switch (rr) {
      case -1:
	switch (errno) {
	case EAGAIN:
	case EINTR:
	  rr = 1;
	  break;
	default:
	  fprintf(stderr, "%s: unable to read child messages: %s\n", name, strerror(errno));
	  fflush(stderr);
	  break;
	}
	break;
      case 0:
	/* eof */
	break;
      default:
	write(STDERR_FILENO, buffer, rr);
	/* don't care if write fails, can't do anything about it */
	break;
      }
    } while (rr > 0);

    sched_yield();
    result = 0;

    if (waitpid(pid, &status, WNOHANG) > 0) {	/* got a child */
      if (WIFEXITED(status)) {
	result = WEXITSTATUS(status);
	fprintf(stderr, "%s: exited with code %d\n", name, result);
      } else if (WIFSIGNALED(status)) {
	fprintf(stderr, "%s: killed by signal %d\n", name, WTERMSIG(status));
	fflush(stderr);
	result = 1;
	/* mimic child - a bad idea, since it smashes any core file */
	/* result = WTERMSIG(status); */
	/* raise(result); */
      } else if (WIFSTOPPED(status)) {	/* clever dick mode */
	result = WSTOPSIG(status);
	fprintf(stderr, "%s: stopped by signal %d, restarting with %d\n", name, result, SIGCONT);
	kill(pid, SIGCONT);
	result = 0;
      }
    }
    /* else child probably ok */
    exit(result);

    break;
  }
}

void drop_fork(char *name)
{
  struct rlimit r;

  r.rlim_cur = 0;
  r.rlim_max = 0;

  if (setrlimit(RLIMIT_NPROC, &r)) {
    fprintf(stderr, "%s: unable to reduce process limit: %s\n", name, strerror(errno));
    exit(1);
  }
}

void drop_root(char *name, char *id, char *rootdir)
{
  uid_t uid = 0;
  gid_t gid = 0;
  struct passwd *pw;

  if (id) {
    uid = atoi(id);
    if (uid <= 0) {
      pw = getpwnam(id);
      if (pw == NULL) {
	fprintf(stderr, "%s: unable to look up user %s\n", name, id);
	exit(1);
      } else {
	uid = pw->pw_uid;
	gid = pw->pw_gid;
	/* docs are unclear - do I need to free pw ? */
	/* free(pw); */
      }
    } else {
      gid = uid;
    }
  } else {
    if (getuid() == 0) {
      fprintf(stderr, "%s: consider having %s drop root privileges\n", name, name);
    }
  }

  if (rootdir != NULL) {	/* do chroot */
    if (chroot(rootdir)) {
      fprintf(stderr, "%s: unable to change root to %s: %s\n", name, rootdir, strerror(errno));
      exit(1);
    }
  }
  chdir("/");

  if (id) {			/* now change id */

    if (setgroups(0, NULL)) {
      fprintf(stderr, "%s: unable to delete supplementary groups: %s\n", name, strerror(errno));
      exit(1);
    }

    if (setgid(gid) || setuid(uid)) {
      fprintf(stderr, "%s: unable to change id to %d/%d: %s\n", name, uid, gid, strerror(errno));
      exit(1);
    }
  }
}
