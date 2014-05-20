#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/poll.h>

#include <idsa.h>
#include <idsa_internal.h>

#include "ucred.h"

#include "structures.h"
#include "functions.h"

int job_end(JOB * j)
{
  int result;

  result = close(j->j_fd);

  return result;
}

int job_read(JOB * j)
{
  int result = 0;
  int rr;
#ifdef TRACE
  int i;
#endif

  if (j->j_rl < IDSA_M_MESSAGE) {
    rr = read(j->j_fd, j->j_rbuf + j->j_rl, IDSA_M_MESSAGE - (j->j_rl));
    switch (rr) {
    case -1:
#ifdef TRACE
      fprintf(stderr, "job_read(): read error: %s\n", strerror(errno));
#endif
      switch (errno) {
      case EINTR:
      case EAGAIN:
	/* nonfatal errors */
	break;
      default:
	result++;
	j->j_state = JOB_STATEFIN;
	break;
      }
      break;
    case 0:
#ifdef TRACE
      fprintf(stderr, "job_read(): eof\n");
#endif
      j->j_state = JOB_STATEFIN;
      break;
    default:

#ifdef TRACE
      fprintf(stderr, "job_read(): read <");
      for (i = 0; i < rr; i++) {
	if (isprint(j->j_rbuf[j->j_rl + i])) {
	  fputc(j->j_rbuf[j->j_rl + i], stderr);
	} else {
	  fprintf(stderr, "\\%02x", (unsigned char) (j->j_rbuf[j->j_rl + i]));
	}
      }
      fprintf(stderr, ":%d>\n", rr);
#endif

      j->j_rl = j->j_rl + rr;
      break;
    }

  } else {
#ifdef TRACE
    fprintf(stderr, "job_read(): too much stuff in buffer\n");
#endif
  }

  return result;
}

int job_write(JOB * j)
{
  int result = 0;

  switch (io_drain(j)) {
  case IDSA_IO_OK:
    j->j_state = JOB_STATEWAIT;
    break;
  case IDSA_IO_WAIT:
    j->j_state = JOB_STATEWRITE;
    break;
  case IDSA_IO_FAIL:
    j->j_state = JOB_STATEFIN;
    result++;
    break;
  }

  return result;
}

void job_copy(JOB * t, JOB * s)
{
  t->j_fd = s->j_fd;

  t->j_pid = s->j_pid;
  t->j_uid = s->j_uid;
  t->j_gid = s->j_gid;

  t->j_state = s->j_state;

  if (s->j_rl > 0) {
    memcpy(t->j_rbuf, s->j_rbuf, s->j_rl);
    t->j_rl = s->j_rl;
  } else {
    t->j_rl = 0;
  }

  if (s->j_wl > 0) {
    memcpy(t->j_wbuf, s->j_wbuf, s->j_wl);
    t->j_wl = s->j_wl;
  } else {
    t->j_wl = 0;
  }
}

int job_do(JOB * j, STATE_SET * s)
{
  int result = 0;

#ifdef TRACE
  fprintf(stderr, "job_do(): state <0x%04x>\n", j->j_state);
#endif

  switch (io_readmessage(s, j, s->s_request)) {
  case IDSA_IO_OK:
#ifdef TRACE
    fprintf(stderr, "job_do(): read event, checking rules\n");
#endif

    idsa_reply_init(s->s_reply);
    idsa_local_init(s->s_chain, s->s_local, s->s_request, s->s_reply);
    result = idsa_chain_run(s->s_chain, s->s_local);
    idsa_local_quit(s->s_chain, s->s_local);

    switch (io_writereply(s, j, s->s_reply)) {
    case IDSA_IO_OK:
      /* j->j_state=JOB_STATEWAIT; */
      break;
    case IDSA_IO_WAIT:
      j->j_state = JOB_STATEWRITE;
      break;
    case IDSA_IO_FAIL:
      j->j_state = JOB_STATEFIN;
      break;
    }

    if (result == IDSA_CHAIN_DROP) {
      j->j_state = JOB_STATEFIN;
    }

    break;
  case IDSA_IO_WAIT:
#ifdef TRACE
    fprintf(stderr, "job_do(): will restart readevent\n");
#endif
    j->j_state = JOB_STATEWAIT;
    break;
  case IDSA_IO_FAIL:
  default:
#ifdef TRACE
    fprintf(stderr, "job_do(): reading event failed, giving up\n");
#endif
    j->j_state = JOB_STATEFIN;
    break;
  }

  return result;
}

int job_accept(JOB * j, int fd)
{
  int result = 0;
  int sl, sd;
  struct sockaddr_un sa;
  IDSA_UCRED cr;
  unsigned int cl;
  int sflags;

  sl = sizeof(struct sockaddr_un);
  sd = accept(fd, (struct sockaddr *) &sa, &sl);

  if (sd != (-1)) {
    j->j_fd = sd;

    fcntl(j->j_fd, F_SETFD, FD_CLOEXEC);

    j->j_rl = 0;
    j->j_wl = 0;

    j->j_state = JOB_STATEWAIT;

#ifdef SO_PEERCRED
    cl = sizeof(IDSA_UCRED);
    if (getsockopt(sd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0) {
      j->j_pid = cr.pid;
      j->j_uid = cr.uid;
      j->j_gid = cr.gid;

#ifdef TRACE
      fprintf(stderr, "job_accept(): Accepted fd<%d>, pid<%d>, uid<%d>\n", j->j_fd, j->j_pid, j->j_uid);
#endif

    } else {
      close(sd);
      result = 1;
    }
#else
    j->j_pid = 0;
    j->j_uid = (-1);
    j->j_gid = (-1);
#endif

    /* only reason to be nonblocking is avoid DoS if write blocks */
    sflags = fcntl(j->j_fd, F_GETFL, 0);
    if ((sflags == (-1))
	|| (fcntl(j->j_fd, F_SETFL, O_NONBLOCK | sflags) == (-1))) {
      close(sd);
      result = 1;
    }
  } else {
    result = 1;
  }

  return result;
}

void job_drop(int fd)
{
  int sl, sd;
  struct sockaddr_un sa;

  sl = sizeof(struct sockaddr_un);
  sd = accept(fd, (struct sockaddr *) &sa, &sl);
  if (sd != (-1)) {
    close(sd);
  }
}
