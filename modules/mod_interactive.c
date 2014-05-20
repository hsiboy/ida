/*
 * usage in rule head: %interactive socketname timeoutvalue failmode
 *
 * This module writes the event to socket, waits until the client
 * sends in a decision or the timeout happens. Then the module writes
 * A<N> or D<N> to the socket, where <N> is the number of the event since 
 * the client first connected to the socket
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <idsa_internal.h>

#define BACKLOG 2		/* I would like to use 1, but things lock */

/****************************************************************************/

struct interactive_socket {
  char is_name[IDSA_M_FILE];
  int is_listen;
  int is_accept;
  unsigned int is_count;

  struct interactive_socket *is_next;
};
typedef struct interactive_socket INTERACTIVE_SOCKET;

struct interactive_entry {
  int ie_failopen;
  struct timeval ie_timeout;

  struct interactive_socket *ie_socket;
};
typedef struct interactive_entry INTERACTIVE_ENTRY;

/****************************************************************************/

static INTERACTIVE_SOCKET *socket_find(INTERACTIVE_SOCKET ** g, IDSA_RULE_CHAIN * c, char *name)
{
  INTERACTIVE_SOCKET *s;

  s = *g;
  while (s && strncmp(s->is_name, name, IDSA_M_FILE - 1)) {
    s = s->is_next;
  }

  return s;
}

static INTERACTIVE_SOCKET *socket_make(INTERACTIVE_SOCKET ** g, IDSA_RULE_CHAIN * c, char *name)
{
  INTERACTIVE_SOCKET *s;
  struct sockaddr_un sa;
  int flags;

  s = socket_find(g, c, name);
  if (s) {
    return s;
  }

  s = malloc(sizeof(INTERACTIVE_SOCKET));
  if (s == NULL) {
    idsa_chain_error_malloc(c, sizeof(INTERACTIVE_SOCKET));
    return NULL;
  }

  strncpy(s->is_name, name, IDSA_M_FILE - 1);
  s->is_name[IDSA_M_FILE - 1] = '\0';
  s->is_accept = -1;

  /* FIXME: possibly do the entire ../common/udomain.c - udomainlisten() here */

  s->is_listen = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s->is_listen < 0) {
    idsa_chain_error_system(c, errno, "unable to create socket");
    free(s);
    return NULL;
  }

  unlink(s->is_name);

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, s->is_name, sizeof(sa.sun_path));
  if (bind(s->is_listen, (struct sockaddr *) &sa, sizeof(sa))) {
    idsa_chain_error_system(c, errno, "unable to bind socket %s", s->is_name);
    close(s->is_listen);
    s->is_listen = (-1);
    free(s);
    return NULL;
  }

  if (listen(s->is_listen, BACKLOG)) {
    idsa_chain_error_system(c, errno, "unable to listen on socket %s", s->is_name);
    unlink(s->is_name);
    close(s->is_listen);
    s->is_listen = (-1);
    free(s);
    return NULL;
  }

  flags = fcntl(s->is_listen, F_GETFL, 0);
  if ((flags == (-1)) || (fcntl(s->is_listen, F_SETFL, O_NONBLOCK | flags) == (-1))) {
    idsa_chain_error_system(c, errno, "unable to make socket %s nonblocking", s->is_name);
    unlink(s->is_name);
    close(s->is_listen);
    s->is_listen = (-1);
    free(s);
    return NULL;
  }

  s->is_next = *g;
  *g = s;

  return s;
}

static int entry_make(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, INTERACTIVE_SOCKET ** g, INTERACTIVE_ENTRY * e)
{
  IDSA_MEX_TOKEN *name, *timeout, *failopen;
  char *tptr;
  char tbuf[7];
  int i;

  e->ie_failopen = 0;
  e->ie_timeout.tv_sec = 0;
  e->ie_timeout.tv_usec = 0;
  e->ie_socket = NULL;

  name = idsa_mex_get(m);
  timeout = idsa_mex_get(m);
  failopen = idsa_mex_get(m);

  if ((name == NULL) || (timeout == NULL) || (failopen == NULL)) {
    idsa_chain_error_mex(c, m);
    return -1;
  }

  e->ie_socket = socket_make(g, c, name->t_buf);
  if (e->ie_socket == NULL) {
    return -1;
  }

  e->ie_timeout.tv_sec = atoi(timeout->t_buf);
  tptr = strchr(timeout->t_buf, '.');
  if (tptr) {
    tptr++;
    for (i = 0; (i < 6) && tptr[i] != '\0'; i++) {
      tbuf[i] = tptr[i];
    }
    for (; i < 6; i++) {
      tbuf[i] = '0';
    }
    tbuf[6] = '\0';
    e->ie_timeout.tv_usec = atoi(tbuf);
  } else {
    e->ie_timeout.tv_usec = 0;
  }

  if (!strcmp(failopen->t_buf, "failopen")) {
    e->ie_failopen = 1;
  }

  return 0;
}

static int entry_compare(INTERACTIVE_ENTRY * a, INTERACTIVE_ENTRY * b)
{
  /* FIXME: makes me feel queasy for some reason */
  return memcmp(a, b, sizeof(INTERACTIVE_ENTRY));
}

static int interactive_accept(INTERACTIVE_SOCKET * s)
{
  int flags, read_result;
  struct sockaddr_un sa;
  int sl;
  char buffer[IDSA_M_MESSAGE];

  if (s->is_accept >= 0) {

#ifdef MSG_NOSIGNAL
    read_result = recv(s->is_accept, buffer, IDSA_M_MESSAGE, MSG_NOSIGNAL);
#else
    read_result = read(s->is_accept, buffer, IDSA_M_MESSAGE);
#endif

    switch (read_result) {
    case -1:
      switch (errno) {
      case EAGAIN:
      case EINTR:
	return 0;		/* bomb: waiting, good */
	break;
      default:
	close(s->is_accept);	/* serious error, try to accept a new one */
	s->is_accept = (-1);
	break;
      }
      break;
    case 0:
      close(s->is_accept);	/* client gone away, try to accept a new one */
      s->is_accept = (-1);
      break;
    default:
      return 0;			/* bomb: read something, socket is active, no need to connect */
    }
  }

  s->is_count = 0;
  sl = sizeof(struct sockaddr_un);
  s->is_accept = accept(s->is_listen, (struct sockaddr *) &sa, &sl);
  if (s->is_accept < 0) {
    return -1;			/* bomb: no client available */
  }

  flags = fcntl(s->is_accept, F_GETFL, 0);
  if ((flags == (-1)) || (fcntl(s->is_accept, F_SETFL, O_NONBLOCK | flags) == (-1))) {
    close(s->is_accept);
    s->is_accept = (-1);
    return -1;			/* bomb: unable to make socket nonblocking */
  }

  return 0;			/* got a new connection */
}

/****************************************************************************/

static void *interactive_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  INTERACTIVE_ENTRY *e;

  e = malloc(sizeof(INTERACTIVE_ENTRY));
  if (e == NULL) {
    idsa_chain_error_malloc(c, sizeof(INTERACTIVE_ENTRY));
    return NULL;
  }

  if (entry_make(m, c, g, e)) {
    free(e);
    return NULL;
  }

  return e;
}

static int interactive_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  INTERACTIVE_ENTRY e;

  if (entry_make(m, c, g, &e)) {
    return -1;
  }

  return entry_compare(t, &e);
}

static void interactive_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  INTERACTIVE_ENTRY *e;
  e = t;

  if (e) {
    e->ie_socket = NULL;
    free(e);
  }
}

static int interactive_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  INTERACTIVE_ENTRY *e;
  INTERACTIVE_SOCKET *s;
  struct timeval tv;
  fd_set fs;
  char buffer[IDSA_M_MESSAGE];
  int should_write, write_result, read_result;
  unsigned int count;
  int result;

  e = t;
  s = e->ie_socket;

  if (interactive_accept(s)) {
    return e->ie_failopen;	/* bomb: unable to get client */
  }

  /* send stuff to the client */
  should_write = idsa_event_tobuffer(q, buffer, IDSA_M_MESSAGE);
  if (should_write <= 0) {
    return e->ie_failopen;	/* bomb: internal error, do not update counter but also don't close */
  }
#ifdef MSG_NOSIGNAL
  write_result = send(s->is_accept, buffer, should_write, MSG_NOSIGNAL);
#else
  write_result = write(s->is_accept, buffer, should_write);
#endif

  if (write_result != should_write) {
#ifdef TRACE
    fprintf(stderr, "interactive_test_do(): write to client failed: %s\n", strerror(errno));
#endif
    close(s->is_accept);
    s->is_accept = (-1);
    return e->ie_failopen;	/* bomb: write to client failed */
  }
  s->is_count++;

  /* await reply */
  FD_ZERO(&fs);
  FD_SET(s->is_accept, &fs);
  tv = e->ie_timeout;

  if (select(s->is_accept + 1, &fs, NULL, NULL, &tv) > 0) {
#ifdef MSG_NOSIGNAL
    read_result = recv(s->is_accept, buffer, IDSA_M_MESSAGE, MSG_NOSIGNAL);
#else
    read_result = read(s->is_accept, buffer, IDSA_M_MESSAGE);
#endif
    if (read_result <= 0) {
#ifdef TRACE
      fprintf(stderr, "interactive_test_do(): read from client failed: %s\n", strerror(errno));
#endif
      close(s->is_accept);
      s->is_accept = (-1);
      return e->ie_failopen;	/* bomb: read from client failed */
    }
    buffer[IDSA_M_MESSAGE - 1] = '\0';
    count = atoi(buffer + 1);
    if (count != s->is_count) {
#ifdef TRACE
      fprintf(stderr, "interactive_test_do(): sync %u!=%u\n", count, s->is_count);
#endif
      close(s->is_accept);
      s->is_accept = (-1);
      return e->ie_failopen;	/* bomb: client out of sync */
    }
    result = (buffer[0] == 'A') ? 1 : 0;
  } else {			/* timeout, fall back */
    result = e->ie_failopen;
  }

  should_write = snprintf(buffer, IDSA_M_MESSAGE, "%c%u\n", result ? 'A' : 'D', s->is_count);

#ifdef MSG_NOSIGNAL
  write_result = send(s->is_accept, buffer, should_write, MSG_NOSIGNAL);
#else
  write_result = write(s->is_accept, buffer, should_write);
#endif
  if (write_result != should_write) {
#ifdef TRACE
    fprintf(stderr, "interactive_test_do(): reply write failed: %s\n", strerror(errno));
#endif
    close(s->is_accept);
    s->is_accept = (-1);
  }

  return result;
}

/****************************************************************************/

static void *interactive_global_start(IDSA_RULE_CHAIN * c)
{
  INTERACTIVE_SOCKET **pointer;

  pointer = malloc(sizeof(INTERACTIVE_SOCKET *));
  if (pointer == NULL) {
    idsa_chain_error_malloc(c, sizeof(INTERACTIVE_SOCKET *));
    return NULL;
  }

  *pointer = NULL;

  return pointer;
}

static void interactive_global_stop(IDSA_RULE_CHAIN * c, void *g)
{
  INTERACTIVE_SOCKET **pointer;
  INTERACTIVE_SOCKET *alpha, *beta;

  pointer = g;

  if (pointer) {
    alpha = *pointer;
    while (alpha) {
      beta = alpha;
      alpha = alpha->is_next;
      unlink(beta->is_name);

      if (beta->is_listen >= 0) {
	close(beta->is_listen);
	beta->is_listen = (-1);
      }
      if (beta->is_accept >= 0) {
	close(beta->is_accept);
	beta->is_accept = (-1);
      }

      free(beta);
    }
    free(pointer);
  }
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_interactive(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "interactive", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->global_start = &interactive_global_start;
    result->global_stop = &interactive_global_stop;

    result->test_start = &interactive_test_start;
    result->test_cache = &interactive_test_cache;
    result->test_do = &interactive_test_do;
    result->test_stop = &interactive_test_stop;
  }

  return result;
}
