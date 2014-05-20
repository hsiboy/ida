#include <time.h>
#include <stdarg.h>

#include <idsa_internal.h>

#include "structures.h"
#include "functions.h"

/****************************************************************************/

/****************************************************************************/
/* Notes      : messsage_chain is different to all other message_*          */
/*              it reports errors generated within libidsa.                 */

int message_chain(STATE_SET * s)
{
  int result = IDSA_CHAIN_OK;

  if (idsa_chain_notice(s->s_chain)) {

    /* s->s_libidsa has already been filled in, only update time */
    idsa_time(s->s_libidsa, s->s_time);

    idsa_reply_init(s->s_reply);
    idsa_local_init(s->s_chain, s->s_local, s->s_libidsa, s->s_reply);
    result = idsa_chain_run(s->s_chain, s->s_local);
    idsa_local_quit(s->s_chain, s->s_local);

    /* restore event for next message */
    idsa_event_copy(s->s_libidsa, s->s_template);

    /* mark s_libidsa available for modification within libidsa again */
    idsa_chain_reset(s->s_chain);
  }

  return result;
}

#define ERROR_BUFFER 1024

int message_stderr(STATE_SET * s)
{
  IDSA_PRINT_HANDLE *ph;
  char buffer[ERROR_BUFFER];
  int l;

  fflush(stderr);

  ph = idsa_print_format("native");
  if (ph) {
    l = idsa_print_do(s->s_libidsa, ph, buffer, ERROR_BUFFER - 1);
    if (l >= 0) {
      write(STDERR_FILENO, buffer, l);
    } else {
      fprintf(stderr, "unable to print error message\n");
    }
    idsa_print_free(ph);
  } else {
    fprintf(stderr, "unable to acquire print handle for error message\n");
  }

  fflush(stderr);

  return 0;
}

/****************************************************************************/

static int message_half(STATE_SET * s)
{
  int result;

  idsa_reply_init(s->s_reply);
  idsa_local_init(s->s_chain, s->s_local, s->s_idsad, s->s_reply);
  result = idsa_chain_run(s->s_chain, s->s_local);
  idsa_local_quit(s->s_chain, s->s_local);

  message_chain(s);

  return result;
}

int message_start(STATE_SET * s, char *v)
{

  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_request_scan(s->s_idsad, "start", "idsa", 0, IDSA_R_SUCCESS, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, "version", IDSA_T_STRING, v, NULL);

  return message_half(s);
}

int message_stop(STATE_SET * s, char *v)
{
  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_request_scan(s->s_idsad, "stop", "idsa", 0, IDSA_R_TOTAL, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, "version", IDSA_T_STRING, v, NULL);

  return message_half(s);
}

int message_connect(STATE_SET * s, pid_t p, uid_t u, gid_t g)
{
  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_request_scan(s->s_idsad, "connect", "idsa", 1, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, NULL);

  idsa_event_setappend(s->s_idsad, "client_pid", IDSA_T_PID, &p);
  idsa_event_setappend(s->s_idsad, "client_uid", IDSA_T_UID, &u);
  idsa_event_setappend(s->s_idsad, "client_gid", IDSA_T_GID, &g);

  return message_half(s);
}

int message_disconnect(STATE_SET * s, pid_t p, uid_t u, gid_t g)
{
  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_request_scan(s->s_idsad, "disconnect", "idsa", 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, NULL);

  idsa_event_setappend(s->s_idsad, "client_pid", IDSA_T_PID, &p);
  idsa_event_setappend(s->s_idsad, "client_uid", IDSA_T_UID, &u);
  idsa_event_setappend(s->s_idsad, "client_gid", IDSA_T_GID, &g);

  return message_half(s);
}

int message_error_system(STATE_SET * s, int err, char *str, ...)
{
  va_list ap;
  va_start(ap, str);

  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_scheme_verror_system(s->s_idsad, err, str, ap);

  va_end(ap);
  return message_half(s);
}

int message_error_internal(STATE_SET * s, char *str, ...)
{
  va_list ap;
  va_start(ap, str);

  idsa_event_copy(s->s_idsad, s->s_template);
  idsa_time(s->s_idsad, s->s_time);

  idsa_scheme_verror_internal(s->s_idsad, str, ap);

  va_end(ap);
  return message_half(s);
}
