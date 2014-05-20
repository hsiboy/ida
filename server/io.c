#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <idsa_internal.h>

#include "structures.h"
#include "functions.h"

int io_readmessage(STATE_SET * s, JOB * j, IDSA_EVENT * e)
{
  int result = IDSA_IO_OK;
  int l;

  l = idsa_event_frombuffer(e, j->j_rbuf, j->j_rl);
  if (l > 0) {
    if (idsa_request_check(e)) {	/* corrupted */
#ifdef TRACE
      fprintf(stderr, "io_readmessage(): message check failed\n");
#endif
      result = IDSA_IO_FAIL;
    } else {
#ifdef TRACE
      idsa_event_dump(e, stderr);
#endif
      if ((j->j_uid != 0) && (j->j_gid != s->s_gid)) {	/* if it is not root or our own group, we don't trust it */
	idsa_uid(e, j->j_uid);
	idsa_gid(e, j->j_gid);
	idsa_pid(e, j->j_pid);

	/* globally cached stuff */
	idsa_time(e, s->s_time);
	idsa_host(e, s->s_hostname);
      }
      result = IDSA_IO_OK;
    }
    memmove(j->j_rbuf, j->j_rbuf + l, j->j_rl - l);
    j->j_rl = j->j_rl - l;
  } else {
    if (j->j_rl < IDSA_M_MESSAGE) {
      result = IDSA_IO_WAIT;
    } else {
#ifdef TRACE
      fprintf(stderr, "io_readmessage(): message %d, too large\n", j->j_rl);
#endif
      result = IDSA_IO_FAIL;
    }
  }

  return result;
}

int io_writereply(STATE_SET * s, JOB * j, IDSA_EVENT * e)
{
  int l;

#ifdef TRACE
  fprintf(stderr, "io_writereply(): writing result, size %d\n", e->e_size);
#endif

  l = idsa_event_tobuffer(e, j->j_wbuf, IDSA_M_MESSAGE);
  if (l > 0) {
    j->j_wl = l;
    return io_drain(j);
  } else {
    return IDSA_IO_FAIL;
  }
}

int io_drain(JOB * j)
{
  int result;
  int wr;

  if (j->j_wl > 0) {
    wr = write(j->j_fd, j->j_wbuf, j->j_wl);
    if (wr == j->j_wl) {
      j->j_wl = 0;
      result = IDSA_IO_OK;
    } else if (wr < 0) {
      switch (errno) {
      case EAGAIN:
      case EINTR:
	result = IDSA_IO_WAIT;
	break;
      default:
	result = IDSA_IO_FAIL;
	break;
      }
    } else if (wr > 0) {	/* some bugger has tried to shrink our pipe ? */
      j->j_wl = j->j_wl - wr;
      memmove(j->j_wbuf, j->j_wbuf + wr, j->j_wl);
      result = IDSA_IO_WAIT;
    } else {
      result = IDSA_IO_WAIT;
    }
  } else {
    result = IDSA_IO_OK;
  }

  return result;
}
