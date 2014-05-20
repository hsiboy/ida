/****************************************************************************/
/*                                                                          */
/*  High level (and hopefully stable) client interface. Allows you to       */
/*  create and report events to the server and look at its response         */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <idsa_internal.h>

/* three filters. Only active if IDSA_F_UPLOAD is set */

#define IDSA_CHN_SERVER 0x01	/* contact server */
#define IDSA_CHN_AUTO   0x02	/* do everything inside client */
#define IDSA_CHN_PRE    0x04	/* contact server for denied events */
#define IDSA_CHN_FAIL   0x08	/* activate if unable to contact server */

static char *idsa_chn_auto = "auto";
static char *idsa_chn_pre = "pre";
static char *idsa_chn_fail = "fail";

#define IDSA_MAX_BACKOFF     255
#define IDSA_DEFAULT_TIMEOUT 300

struct idsa_connection {
  int c_fd;			/* fd to idsad */
  int c_result;

  int c_error;
  int c_backoff;
  int c_fresh;			/* new error to be reported */
  int c_timeout;		/* longest time to stay in call if no IDSA_F_UPLOAD */

  unsigned int c_flags;		/* flags: failopen, etc */

  char c_service[IDSA_M_STRING];	/* service name: for resetting template */
  char c_credential[IDSA_M_STRING];	/* unused */

  IDSA_EVENT *c_template;	/* template for other events */
  IDSA_EVENT *c_cache;		/* simple cache for malloc */
  IDSA_EVENT *c_reply;		/* read reply */
  IDSA_EVENT *c_internal;	/* event for internal errors/messages */

  char c_reason[IDSA_M_STRING];

  int c_filter;
  IDSA_RULE_CHAIN *c_chain;	/* table of rules */
  IDSA_RULE_LOCAL *c_local;	/* arguments sent to rule interpreter */

#ifdef WANTS_PROF
  clock_t c_libtime;
  clock_t c_systime;
  clock_t c_waltime;
  int c_profnum;
#endif
};

static int idsa_client_connect(IDSA_CONNECTION * c);
static int idsa_client_write(IDSA_CONNECTION * c, IDSA_EVENT * e);
static int idsa_client_read(IDSA_CONNECTION * c, IDSA_EVENT * e);
static int idsa_client_io(IDSA_CONNECTION * c, IDSA_EVENT * q, IDSA_EVENT * p);

static int idsa_putenv(IDSA_UNIT * u);

static void idsa_client_reclaim(IDSA_CONNECTION * c, IDSA_EVENT * e);
static int idsa_client_rule(IDSA_CONNECTION * c, IDSA_EVENT * e);
static int idsa_client_install(IDSA_CONNECTION * c, IDSA_UNIT * u, int number, int file);
static int idsa_client_reply(IDSA_CONNECTION * c);

#ifdef FALLBACK
static int idsa_client_standalone(IDSA_CONNECTION * c);
#endif

static void idsa_client_error_internal(IDSA_CONNECTION * c, char *s, ...);
#if 0
static void idsa_client_handle_error(IDSA_CONNECTION * c);
#endif

/* unused
static void idsa_client_error_system(IDSA_CONNECTION * c, int err, char *s, ...);
*/

static volatile int idsa_alarm_set = 0;

/****************************************************************************/
/* Does       : notices if an alarm has happened                            */
/* Parameters :                                                             */
/* Returns    :                                                             */
/* Errors     :                                                             */
/* Notes      : only gets involved if IDSA_F_TIMEOUT is used                */

static void idsa_alarm_handle(int s)
{
  idsa_alarm_set = 1;
}

/****************************************************************************/
/* Does       : set up the entire thing                                     */
/* Parameters : service - your name, credential - NULL for the time being   */
/*              flags - IDSA_F_*                                            */
/* Returns    : pointer to connection structure on success, else NULL       */

IDSA_CONNECTION *idsa_open(char *service, char *credential, int flags)
{
  IDSA_CONNECTION *c;
#ifndef MSG_NOSIGNAL
  struct sigaction sag;
#endif

  if (service == NULL) {
    return NULL;
  }

  c = malloc(sizeof(IDSA_CONNECTION));
  if (c == NULL) {
    return c;
  }

  c->c_fd = (-1);
  c->c_result = 0;

  c->c_error = 0;
  c->c_backoff = 1;
  c->c_fresh = 0;
  c->c_timeout = IDSA_DEFAULT_TIMEOUT;

  c->c_flags = flags;

  /* previously checked that service != NULL */
  strncpy(c->c_service, service, IDSA_M_STRING - 1);
  c->c_service[IDSA_M_STRING - 1] = '\0';

  if (credential) {
    strncpy(c->c_credential, credential, IDSA_M_STRING);
    c->c_credential[IDSA_M_STRING - 1] = '\0';
  } else {
    c->c_credential[0] = '\0';
  }

  /* allocate 4 events */
  c->c_cache = idsa_event_new(0);
  c->c_template = idsa_event_new(0);
  c->c_reply = idsa_event_new(0);
  c->c_internal = idsa_event_new(0);

  c->c_reason[0] = '\0';

  c->c_filter = IDSA_CHN_SERVER;
  c->c_chain = NULL;
  c->c_local = NULL;

#ifdef WANTS_PROF
  c->c_systime = 0;
  c->c_libtime = 0;
  c->c_waltime = 0;
  c->c_profnum = 0;
#endif

  if ((c->c_cache == NULL) || (c->c_template == NULL)
      || (c->c_reply == NULL) || (c->c_internal == NULL)) {
    idsa_close(c);
    return NULL;
  }

  /* Signal stuff not needed if send(...,MSG_NOSIGNAL); available */
#ifndef MSG_NOSIGNAL
  /* By default we ignore sigpipe in case idsad goes away. If the application needs to receive SIGPIPE, pass the IDSA_F_SIGPIPE at the risk of causing problems if idsad goes away */
  if (!(flags & IDSA_F_SIGPIPE)) {
    sag.sa_handler = SIG_IGN;
    sigfillset(&(sag.sa_mask));
    sag.sa_flags = SA_RESTART;
    sigaction(SIGPIPE, &sag, NULL);
  }
#endif

  /* fill in the defaults for an event request */
  idsa_request_init(c->c_template, c->c_service, c->c_service, c->c_service);

#ifdef FALLBACK
  if (idsa_client_connect(c)) {
    idsa_client_standalone(c);
  }
#else
  idsa_client_connect(c);	/* start talking to other side */
#endif

  return c;
}

/****************************************************************************/
/* Does       : Close and re-open a connection. Should be called after a    */
/*              fork                                                        */

int idsa_reset(IDSA_CONNECTION * c)
{
  int result;

  if (c == NULL) {
    return 0;
  }

  if (c->c_chain) {		/* clean out previous */
    if (c->c_local) {
      idsa_local_free(c->c_chain, c->c_local);
      c->c_local = NULL;
    }
    idsa_chain_stop(c->c_chain);
    c->c_chain = NULL;
  }

  idsa_request_init(c->c_template, c->c_service, c->c_service, c->c_service);

  result = idsa_client_connect(c);

#ifdef FALLBACK
  if (result) {
    result = idsa_client_standalone(c);
  }
#endif

  return result;
}

/****************************************************************************/
/* Does       : Deallocate resources associated with connection (close file */
/*              descriptor and release memory)                              */

int idsa_close(IDSA_CONNECTION * c)
{
  int result = 0;

  if (c != NULL) {
    /* zap last event */
    if (c->c_cache != NULL) {
      idsa_event_free(c->c_cache);
      c->c_cache = NULL;
    }
    if (c->c_template != NULL) {
      idsa_event_free(c->c_template);
      c->c_template = NULL;
    }
    if (c->c_reply != NULL) {
      idsa_event_free(c->c_reply);
      c->c_reply = NULL;
    }
    if (c->c_internal != NULL) {
      idsa_event_free(c->c_internal);
      c->c_internal = NULL;
    }
    /* zap connection */
    if (c->c_fd != (-1)) {
      result = close(c->c_fd);
      c->c_fd = (-1);
    }

    if (c->c_chain) {
      if (c->c_local) {
	idsa_local_free(c->c_chain, c->c_local);
	c->c_local = NULL;
      }
      idsa_chain_stop(c->c_chain);
      c->c_chain = NULL;
    }
    c->c_filter = IDSA_CHN_SERVER;

    free(c);
  }
  return result;
}

/* single line usage ******************************************************* */

/****************************************************************************/
/* Does       : creates an event from arguments and logs it. The variable   */
/*              argument list is given as a triple of name, type and value  */
/*              where the value is represented as a string. The list is     */
/*              terminated by a null name string                            */

int idsa_scan(IDSA_CONNECTION * c, char *n, char *s, int f, unsigned cr, unsigned ar, unsigned ir, ...)
{
  IDSA_EVENT *e;
  va_list ap;
  int result = IDSA_L_DENY;
#ifdef WANTS_PROF
  struct tms start, stop;
  clock_t wall;
#endif

#ifdef WANTS_PROF
  wall = times(&start);
  c->c_profnum++;
#endif

  va_start(ap, ir);

  if (c) {			/* major failure */
    e = idsa_event(c);
    if (e) {
      if (idsa_request_vscan(e, n, s, f, cr, ar, ir, ap)) {
	idsa_free(c, e);
	if (c->c_flags & IDSA_F_FAILOPEN) {
	  result = IDSA_L_ALLOW;
	}
      } else {
	/* log does its own free */
	result = idsa_log(c, e);
	/* unless somebody set the KEEP flag (ouch) */
	if (c->c_flags & IDSA_F_KEEP) {
	  idsa_free(c, e);
	}
      }

    } else {
      if (c->c_flags & IDSA_F_FAILOPEN) {
	result = IDSA_L_ALLOW;
      }
    }
  }
  va_end(ap);

#ifdef WANTS_PROF
  wall = (times(&stop) - wall);
  c->c_waltime = c->c_libtime + wall;
  c->c_libtime = c->c_libtime + stop.tms_utime - start.tms_utime;
  c->c_systime = c->c_systime + stop.tms_stime - start.tms_stime;
#endif

  return result;
}

/****************************************************************************/
/* Does       : creates an event from arguments and logs it. The variable   */
/*              argument list is given as a triple of name, type and value  */
/*              where the value is a pointer. The list is terminated by a   */
/*              null name string                                            */

int idsa_set(IDSA_CONNECTION * c, char *n, char *s, int f, unsigned cr, unsigned ar, unsigned ir, ...)
{
  IDSA_EVENT *e;
  va_list ap;
  int result = IDSA_L_DENY;

#ifdef WANTS_PROF
  struct tms start, stop;
  clock_t wall;
#endif

#ifdef WANTS_PROF
  wall = times(&start);
  c->c_profnum++;
#endif

  va_start(ap, ir);

  if (c) {			/* major failure */
    e = idsa_event(c);
    if (e) {
      if (idsa_request_vset(e, n, s, f, cr, ar, ir, ap)) {
	idsa_free(c, e);
	if (c->c_flags & IDSA_F_FAILOPEN) {
	  result = IDSA_L_ALLOW;
	}
      } else {
	/* log does its own free */
	result = idsa_log(c, e);
	/* unless somebody set the KEEP flag (ouch) */
	if (c->c_flags & IDSA_F_KEEP) {
	  idsa_free(c, e);
	}
      }

    } else {
      if (c->c_flags & IDSA_F_FAILOPEN) {
	result = IDSA_L_ALLOW;
      }
    }
  }
  va_end(ap);

#ifdef WANTS_PROF
  wall = (times(&stop) - wall);
  c->c_waltime = c->c_libtime + wall;
  c->c_libtime = c->c_libtime + stop.tms_utime - start.tms_utime;
  c->c_systime = c->c_systime + stop.tms_stime - start.tms_stime;
#endif

  return result;
}

/* event setup ************************************************************* */

/****************************************************************************/
/* Does       : return a new event which can later be logged. The event     */
/*              contains reasonable defaults which can be modified with     */
/*              with idsa_template                                          */
/* Parameters : pointer to event, NULL on failure                           */

IDSA_EVENT *idsa_event(IDSA_CONNECTION * c)
{
  IDSA_EVENT *result;

  if (c) {
    if (c->c_cache == NULL) {
      result = idsa_event_new(0);
    } else {
      result = c->c_cache;
      c->c_cache = NULL;
    }
    if (result) {
      idsa_event_copy(result, c->c_template);
    }
  } else {
    result = NULL;
  }

  return result;
}

/****************************************************************************/
/* Does       : Make event e the template for all subsequent calls to       */
/*              idsa_event                                                  */
/* Parameters : e - event to use as template, if NULL revert to original    */

void idsa_template(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  if (c) {
    if (e) {
      idsa_event_copy(c->c_template, e);
    } else {
      /* idsa_request */
      idsa_request_init(c->c_template, c->c_service, c->c_service, c->c_service);
    }

    if (!(c->c_flags & IDSA_F_KEEP)) {
      idsa_free(c, e);
    }
  }
}

/****************************************************************************/
/* Does       : release event memory, only required if F_KEEP set           */

void idsa_free(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  if (c) {
    if (c->c_cache == NULL) {
      c->c_cache = e;
    } else {
      idsa_event_free(e);
    }
  } else {
    idsa_event_free(e);
  }
}

/* modify required fields ************************************************** */

/****************************************************************************/
/* Does       : Sets process id of event                                    */

int idsa_pid(IDSA_EVENT * e, pid_t p)
{
  return idsa_request_pid(e, p);
}

/****************************************************************************/
/* Does       : Sets owner of event                                         */

int idsa_uid(IDSA_EVENT * e, uid_t u)
{
  return idsa_request_uid(e, u);
}

/****************************************************************************/
/* Does       : Sets group owner of event                                   */

int idsa_gid(IDSA_EVENT * e, gid_t g)
{
  return idsa_request_gid(e, g);
}

/****************************************************************************/
/* Does       : Sets event timestamp                                        */
/* Notes      : Pointless, log will overwrite it                            */

int idsa_time(IDSA_EVENT * e, time_t t)
{
  return idsa_request_time(e, t);
}

/****************************************************************************/
/* Does       : Sets hostname for this event                                */

int idsa_host(IDSA_EVENT * e, char *h)
{
  return idsa_request_host(e, h);
}

/****************************************************************************/
/* Does       : Sets name field for event                                   */

int idsa_name(IDSA_EVENT * e, char *n)
{
  return idsa_request_name(e, n);
}

/****************************************************************************/
/* Does       : Sets scheme/namespace for event                             */

int idsa_scheme(IDSA_EVENT * e, char *s)
{
  return idsa_request_scheme(e, s);
}

/****************************************************************************/
/* Does       : Sets service name for event                                 */

int idsa_service(IDSA_EVENT * e, char *s)
{
  return idsa_request_service(e, s);
}

/****************************************************************************/
/* Does       : Sets risk rating of event                                   */

int idsa_risks(IDSA_EVENT * e, int f, unsigned a, unsigned c, unsigned i)
{
  return idsa_request_risks(e, f, a, c, i);
}

/****************************************************************************/
/* Does       : Sets flag indicating if a deny will be honoured             */

int idsa_honour(IDSA_EVENT * e, int f)
{
  return idsa_request_honour(e, f);
}

/* add more fields ********************************************************* */

/****************************************************************************/
/* Does       : Lets you explain your event to the sysadmin                 */

int idsa_comment(IDSA_EVENT * e, char *m, ...)
{
  int result;
  va_list ap;

  va_start(ap, m);
  result = idsa_add_vprintf(e, idsa_resolve_name(IDSA_O_COMMENT), m, ap);
  va_end(ap);

  return result;
}

/****************************************************************************/
/* Does       : Adds a string using using a printf syntax                   */

int idsa_add_printf(IDSA_EVENT * e, char *n, char *s, ...)
{
  int result;
  va_list ap;

  va_start(ap, s);
  result = idsa_add_vprintf(e, n, s, ap);
  va_end(ap);

  return result;
}

/****************************************************************************/
/* Does       : Adds a string using vsprintf                                */

int idsa_add_vprintf(IDSA_EVENT * e, char *n, char *s, va_list ap)
{
  int result = 0;
  char buffer[IDSA_M_STRING];

  vsnprintf(buffer, IDSA_M_STRING, s, ap);
  buffer[IDSA_M_STRING - 1] = '\0';
  if (idsa_event_scanappend(e, n, IDSA_T_STRING, buffer)) {
    result = 1;
  }

  return result;
}

/****************************************************************************/
/* Does       : Append a string unit to event                               */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_add_string(IDSA_EVENT * e, char *n, char *s)
{
  if (idsa_event_scanappend(e, n, IDSA_T_STRING, s)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Append an integer unit to event                             */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_add_integer(IDSA_EVENT * e, char *n, int i)
{
  if (idsa_event_setappend(e, n, IDSA_T_INT, &i)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Append any type to event (access to more than int or string) */
/* Parameters : n - name of field, t - its type, s - pointer to data        */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_add_scan(IDSA_EVENT * e, char *n, unsigned int t, char *s)
{
  if (idsa_event_scanappend(e, n, t, s)) {
    return 0;
  } else {
    return 1;
  }
}

int idsa_add_set(IDSA_EVENT * e, char *n, unsigned int t, void *p)
{
  /* IDSA_UNIT *u; */
  if (idsa_event_setappend(e, n, t, p)) {
    /* return idsa_unit_check(u); */
    return 0;
  } else {
    return 1;
  }
}

int idsa_add_unit(IDSA_EVENT * e, IDSA_UNIT * u)
{
  IDSA_UNIT *t;
  t = idsa_event_unitappend(e, u);
  if (t) {
    return 0;
  } else {
    return 1;
  }
}

/* logging and its results ************************************************* */

/****************************************************************************/
/* Does       : Returns nonzero if an error has occured, generally little   */
/*              reason to look at it                                        */

int idsa_error(IDSA_CONNECTION * c)
{
  return c->c_error;
}

/****************************************************************************/
/* Does       : Returns a string containing an reason for the last          */
/*              L_* code of idsa_log, if available, otherwise NULL          */

char *idsa_reason(IDSA_CONNECTION * c)
{
  if (c->c_reason[0] == '\0') {
    return NULL;
  }
  return c->c_reason;
}

/****************************************************************************/
/* Does       : send event off to other side, delete event unless F_KEEP    */
/*              set.                                                        */
/* Returns    : L_OK if request allowed, L_DENY if not                      */

int idsa_log(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  int result;

  if (c == NULL) {
    /* the user deserves a core dump, but... */
    return IDSA_L_DENY;
  }

  result = (c->c_flags & IDSA_F_FAILOPEN) ? IDSA_L_ALLOW : IDSA_L_DENY;

  if (e == NULL) {
    /* can't call reclaim, as in all subsequent returns out of this function */
    return result;
  }

  idsa_time(e, time(NULL));

  if (c->c_filter & IDSA_CHN_AUTO) {	/* operate autonomously - don't bother with server */
    idsa_chain_setname(c->c_chain, idsa_chn_auto);
    result = idsa_client_rule(c, e);
  } else {			/* contact server */
    if (c->c_filter & IDSA_CHN_PRE) {	/* try prefilter */
      idsa_chain_setname(c->c_chain, idsa_chn_pre);
      result = idsa_client_rule(c, e);
    }
    if ((!(c->c_filter & IDSA_CHN_PRE)) || (result == IDSA_L_DENY)) {	/* prefilter not active */
      if (idsa_client_io(c, e, c->c_reply) == 0) {	/* remote side was ok */
	result = idsa_client_reply(c);
      } else {			/* remote side didn't work */
	if (c->c_filter & IDSA_CHN_FAIL) {	/* try error handler */
	  idsa_chain_setname(c->c_chain, idsa_chn_fail);
	  result = idsa_client_rule(c, e);
	}
      }
    }
  }

  idsa_client_reclaim(c, e);

  return result;
}

/****************************************************************************/
/* internal functions ****************************************************** */

static void idsa_client_reclaim(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  if (!(c->c_flags & IDSA_F_KEEP)) {
    idsa_free(c, e);
  }
}

/****************************************************************************/
/* Does       : processes units sent in reply                               */

static int idsa_client_reply(IDSA_CONNECTION * c)
{
  int result;
  unsigned int i, name, type, delay;
  int m;
  IDSA_EVENT *e;
  IDSA_UNIT *u;

  c->c_reason[0] = '\0';

  e = c->c_reply;

  /* first do required fields */
  result = idsa_reply_result(e);

  /* now do optional fields, if any */
  for (i = idsa_reply_count(); i < e->e_count; i++) {
    u = idsa_event_unitbynumber(e, i);
    if (u) {
      name = idsa_resolve_code(idsa_unit_name_get(u));
      type = idsa_resolve_type(name, NULL);

      if (idsa_unit_type(u) == type) {
	switch (name) {
	case IDSA_O_REASON:
	  m = idsa_unit_print(u, c->c_reason, IDSA_M_STRING - 1, 0);
	  c->c_reason[(m < 0) ? 0 : m] = '\0';
	  break;

	case IDSA_O_AUTORULE:
	  idsa_client_install(c, u, IDSA_CHN_AUTO, 0);
	  if (c->c_local && (c->c_fd != (-1))) {	/* never go back to idsad */
	    close(c->c_fd);
	    c->c_fd = (-1);
	  }
	  break;
	case IDSA_O_AUTOFILE:
	  idsa_client_install(c, u, IDSA_CHN_AUTO, 1);
	  if (c->c_local && (c->c_fd != (-1))) {	/* never go back to idsad */
	    close(c->c_fd);
	    c->c_fd = (-1);
	  }
	  break;

	case IDSA_O_PRERULE:
	  idsa_client_install(c, u, IDSA_CHN_PRE, 0);
	  break;
	case IDSA_O_PREFILE:
	  idsa_client_install(c, u, IDSA_CHN_PRE, 1);
	  break;

	case IDSA_O_FAILRULE:
	  idsa_client_install(c, u, IDSA_CHN_FAIL, 0);
	  break;
	case IDSA_O_FAILFILE:
	  idsa_client_install(c, u, IDSA_CHN_FAIL, 1);
	  break;

	case IDSA_O_BOTHRULE:
	  idsa_client_install(c, u, IDSA_CHN_PRE | IDSA_CHN_FAIL, 0);
	  break;
	case IDSA_O_BOTHFILE:
	  idsa_client_install(c, u, IDSA_CHN_PRE | IDSA_CHN_FAIL, 1);
	  break;

	case IDSA_O_SLEEP:
	  idsa_unit_get(u, &delay, sizeof(int));
	  if (delay > 0) {
	    sleep(delay);
	  }
	  break;
	case IDSA_O_STOP:
	  raise(SIGSTOP);
	  break;
	case IDSA_O_ENV:
	  if (c->c_flags & IDSA_F_UPLOAD) {
	    idsa_putenv(u);
	  }
	  break;

	default:		/* ignore unknown fields */
	  break;
	}
      }
    }
  }

#if 0
  idsa_client_handle_error(c);
#endif

  return result;
}

/****************************************************************************/

static int idsa_putenv(IDSA_UNIT * u)
{
  char buffer[IDSA_M_MESSAGE];
  char *value;
  int len, result;

  /* get hold of string representation */
  len = idsa_unit_print(u, buffer, IDSA_M_MESSAGE - 1, 0);
  result = (-1);

  len = idsa_unit_print(u, buffer, IDSA_M_MESSAGE - 1, 0);
  if (len > 0) {
    buffer[len] = '\0';
    value = strchr(buffer, '=');
    if (value) {
      *value = '\0';
      value++;
      result = setenv(buffer, value, 1);
    }
  }

  return result;
}

/****************************************************************************/
/* Does       : Gets environment variable if ok to do so                    */

static char *idsa_getenv(IDSA_CONNECTION * c, char *label)
{
  if (label) {
    if (c->c_flags & IDSA_F_ENV) {
      /* I wonder if this is wise - setuid should never use this option */
      /* so maybe nanny test if effective uid != real uid ? */
      return getenv(label);
    } else {
      return NULL;
    }
  } else {
    return NULL;
  }
}

/****************************************************************************/
/* Does       : Tries to open /etc/idsa.d/service for rule list             */
/* Returns    : zero, interesting value in c->c_filter                      */

static int idsa_client_standalone(IDSA_CONNECTION * c)
{
  char buffer[IDSA_M_MESSAGE];
  char *f;
  IDSA_EVENT *failure;

  c->c_filter = IDSA_CHN_SERVER;

  if (c->c_chain) {		/* clean out previous */
    if (c->c_local) {
      idsa_local_free(c->c_chain, c->c_local);
      c->c_local = NULL;
    }
    idsa_chain_stop(c->c_chain);
    c->c_chain = NULL;
  }

  if (c->c_fresh == 0) {	/* no previous errors */
    failure = c->c_internal;
    idsa_event_copy(failure, c->c_template);
  } else {			/* otherwise don't clobber earliest error */
    failure = NULL;
  }

  f = idsa_getenv(c, "IDSA_CONFIG");
  snprintf(buffer, IDSA_M_MESSAGE - 1, "%s/%s", f ? f : IDSA_CONFIG, c->c_service);
  buffer[IDSA_M_MESSAGE - 1] = '\0';

  c->c_chain = idsa_parse_file(failure, buffer, 0);
  if (c->c_chain) {		/* rule chain ok, now set up caller "context" */
    c->c_local = idsa_local_new(c->c_chain);
    if (c->c_local) {		/* success */
      c->c_filter = IDSA_CHN_AUTO;
    } else {			/* failure */
      idsa_chain_stop(c->c_chain);
      c->c_chain = NULL;
      c->c_fresh = 1;		/* say that we have an error */
    }
  } else {
    c->c_fresh = 1;		/* simulate a idsa_client_error_* action */
  }

  return 0;
}

/****************************************************************************/
/* Does       : Installs a rule chain into the client context. Only does    */
/*              something if IDSA_F_UPLOAD has been set during idsa_open()  */
/*              as it requires a greater trust in idsa                      */

static int idsa_client_install(IDSA_CONNECTION * c, IDSA_UNIT * u, int number, int file)
{
  char buffer[IDSA_M_MESSAGE];
  int len;
  IDSA_EVENT *failure;


  /* FIXME: needs error logging */
/*
  idsa_request_init(error, c->c_service, "idsa", "error");
*/

  c->c_filter = IDSA_CHN_SERVER;
  if (c->c_flags & IDSA_F_UPLOAD) {
    if (c->c_chain) {		/* clean out previous */
      if (c->c_local) {
	idsa_local_free(c->c_chain, c->c_local);
	c->c_local = NULL;
      }
      idsa_chain_stop(c->c_chain);
      c->c_chain = NULL;
    }

    /* get hold of string representation */
    len = idsa_unit_print(u, buffer, IDSA_M_MESSAGE - 1, 0);
    if (len > 0) {
      buffer[len] = '\0';

      if (c->c_fresh == 0) {	/* no previous errors */
	failure = c->c_internal;
	idsa_event_copy(failure, c->c_template);
      } else {			/* otherwise don't clobber earliest error */
	failure = NULL;
      }

      if (file) {
	c->c_chain = idsa_parse_file(failure, buffer, 0);
      } else {
	c->c_chain = idsa_parse_buffer(failure, buffer, len, 0);
      }

      if (c->c_chain) {		/* rule chain ok, now set up caller "context" */
	c->c_local = idsa_local_new(c->c_chain);
	if (c->c_local) {	/* success */
	  c->c_filter = number;
	} else {		/* failure */
	  idsa_chain_stop(c->c_chain);
	  c->c_chain = NULL;
	  c->c_fresh = 1;	/* say that we have an error */
	}
      } else {
	c->c_fresh = 1;		/* simulate a idsa_client_error_* action */
      }
    } else {
      idsa_client_error_internal(c, "unable to acquire string containg rules");
    }
  } else {
    idsa_client_error_internal(c, "client side processing not enabled (use IDSA_F_UPLOAD)");
  }

  return 0;
}

/****************************************************************************/
/* Does       : Runs a previously uploaded rule                             */
/* Notes      : Paranoids might want to do a bounds check on number         */

static int idsa_client_rule(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  IDSA_RULE_CHAIN *chain;
  IDSA_RULE_LOCAL *local;
  int result;

  chain = c->c_chain;
  local = c->c_local;

  idsa_reply_init(c->c_reply);

  idsa_local_init(chain, local, e, c->c_reply);
  idsa_chain_run(chain, local);
  idsa_local_quit(chain, local);

  result = idsa_reply_result(c->c_reply);

  return result;
}

/* client server io *********************************************************/

/****************************************************************************/
/* Does       : Talks to the other side, with linear backoff strategy       */

static int idsa_client_io(IDSA_CONNECTION * c, IDSA_EVENT * q, IDSA_EVENT * p)
{
  if (c->c_error % (c->c_backoff)) {	/* linear backoff */
#ifdef DEBUG
    fprintf(stderr, "idsa_client_io(): backoff active, %d/%d\n", c->c_error, c->c_backoff);
#endif
    c->c_error = c->c_error + 1;
    return 1;
  }

  if (c->c_error == 0) {	/* no previous errors, attempt a normal write */
    if (idsa_client_write(c, q) < 0) {
      c->c_error = 1;
#ifdef DEBUG
      fprintf(stderr, "idsa_io(): write request failed\n");
#endif
    }
  }

  /* FIXME: possibly report errors here using c_internal/c_fresh */

  if (c->c_error > 0) {		/* one retry after the first failure */
    if (c->c_fd != (-1)) {	/* close broken connection */
      close(c->c_fd);
      c->c_fd = (-1);
    }
    if (idsa_client_connect(c)) {	/* failed to connect */
      if (!((c->c_flags & IDSA_F_NOBACKOFF) || (c->c_backoff >= IDSA_MAX_BACKOFF))) {
	c->c_backoff = c->c_backoff + 1;
      }
      c->c_error = 1;
      return 1;
    }
    if (idsa_client_write(c, q) < 0) {	/* failed to write, again */
      if (!((c->c_flags & IDSA_F_NOBACKOFF) || (c->c_backoff >= IDSA_MAX_BACKOFF))) {
	c->c_backoff = c->c_backoff + 1;
      }
      c->c_error = 1;
      return 1;
    }
#ifdef DEBUG
    fprintf(stderr, "idsa_client_io(): reconnect succeeded\n");
#endif
    c->c_backoff = 1;
    c->c_error = 0;
  }

  /* write ok, now try to get reply */
  if (idsa_client_read(c, p) < 0) {	/* read failed */
    c->c_error = 1;
#ifdef DEBUG
    fprintf(stderr, "idsa_log(): client read failed\n");
#endif
    return 1;
  }

  if (idsa_reply_check(p)) {	/* got something, but it is corrupted */
    c->c_error = 1;
#ifdef DEBUG
    fprintf(stderr, "idsa_client_io(): reply is broken\n");
#endif
    return 1;
  }

  return 0;
}

/****************************************************************************/
/* Does       : Send something to the other side, hoping that tobuffer does */
/*              a decent conversion                                         */

static int idsa_client_write(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  char buffer[IDSA_M_MESSAGE];
  int should_write, have_written, write_result;
  struct sigaction nag, sag;
  unsigned int salr;

  should_write = idsa_event_tobuffer(e, buffer, IDSA_M_MESSAGE);
  if (should_write <= 0) {
    return -1;
  }

  salr = 0;
  if (c->c_flags & IDSA_F_TIMEOUT) {
    salr = alarm(c->c_timeout);
    nag.sa_handler = idsa_alarm_handle;
    sigfillset(&(nag.sa_mask));
    nag.sa_flags = 0;
    sigaction(SIGALRM, &nag, &sag);
  }

  have_written = 0;
  do {
#ifdef MSG_NOSIGNAL
    write_result = send(c->c_fd, buffer + have_written, should_write - have_written, MSG_NOSIGNAL);
#else
    write_result = write(c->c_fd, buffer + have_written, should_write - have_written);
#endif
    if (write_result < 0) {
      switch (errno) {
      case EAGAIN:
      case EINTR:
	if (idsa_alarm_set == 0) {
	  write_result = 0;
	}
	break;
      default:
	break;
      }
    } else {
      have_written += write_result;
    }
  } while ((write_result >= 0) && (have_written < should_write));

  if (c->c_flags & IDSA_F_TIMEOUT) {
    alarm(salr);
    sigaction(SIGALRM, &sag, NULL);
    idsa_alarm_set = 0;
  }

  if (have_written < should_write) {
    return -1;
  }
  return should_write;
}

static int idsa_client_read(IDSA_CONNECTION * c, IDSA_EVENT * e)
{
  char buffer[IDSA_M_MESSAGE];
  int read_result, have_read, have_copied, result;
  struct sigaction nag, sag;
  int salr;

  salr = 0;
  if (c->c_flags & IDSA_F_TIMEOUT) {
    salr = alarm(c->c_timeout);
    nag.sa_handler = idsa_alarm_handle;
    sigfillset(&(nag.sa_mask));
    nag.sa_flags = 0;
    sigaction(SIGALRM, &nag, &sag);
  }

  have_read = 0;
  have_copied = (-1);

  do {
#ifdef MSG_NOSIGNAL
    read_result = recv(c->c_fd, buffer + have_read, IDSA_M_MESSAGE - have_read, MSG_NOSIGNAL);
#else
    read_result = read(c->c_fd, buffer + have_read, IDSA_M_MESSAGE - have_read);
#endif
    if (read_result < 0) {
      switch (errno) {
      case EAGAIN:
      case EINTR:
	if (idsa_alarm_set) {
	  have_read = IDSA_M_MESSAGE;
	}
	break;
      default:
	have_read = IDSA_M_MESSAGE;
	break;
      }
    } else if (read_result == 0) {
      have_read = IDSA_M_MESSAGE;
    } else {
      have_read += read_result;
      have_copied = idsa_event_frombuffer(e, buffer, have_read);
    }

  } while ((have_read < IDSA_M_MESSAGE) && (have_copied < 0));

  if (c->c_flags & IDSA_F_TIMEOUT) {
    alarm(salr);
    sigaction(SIGALRM, &sag, NULL);
    idsa_alarm_set = 0;
  }

  if (have_copied == have_read) {
    result = have_copied;
  } else {
    result = (-1);
  }

  return result;
}

static int idsa_client_connect(IDSA_CONNECTION * c)
{
  struct sockaddr_un addr;
  char *f;
  struct sigaction nag, sag;
  int salr;
  int result;

  if (c->c_fd != (-1)) {
    close(c->c_fd);
    c->c_fd = (-1);
  }

  f = idsa_getenv(c, "IDSA_SOCKET");

  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, f ? f : IDSA_SOCKET, sizeof(addr.sun_path));
  c->c_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (c->c_fd == (-1)) {
    return -1;
  }

  salr = 0;
  if (c->c_flags & IDSA_F_TIMEOUT) {
    salr = alarm(c->c_timeout);

    nag.sa_handler = idsa_alarm_handle;
    sigfillset(&(nag.sa_mask));
    nag.sa_flags = 0;

    sigaction(SIGALRM, &nag, &sag);
  }

  result = connect(c->c_fd, (struct sockaddr *) &addr, sizeof(addr));

  if (c->c_flags & IDSA_F_TIMEOUT) {
    alarm(salr);
    sigaction(SIGALRM, &sag, NULL);
    idsa_alarm_set = 0;
  }

  if (result) {
    close(c->c_fd);
    c->c_fd = (-1);
    return -1;
  }

  fcntl(c->c_fd, F_SETFD, 1);	/* only one at a time please. Anybody know of a close on fork/thread ? */

  return 0;
}

/* error handling code ******************************************************/

#if 0
static void idsa_client_handle_error(IDSA_CONNECTION * c)
{
  if (c->c_fresh) {
    idsa_client_io(c, c->c_internal, c->c_reply);
    c->c_fresh = 0;
  }
}
#endif

/* unused
static void idsa_client_error_system(IDSA_CONNECTION * c, int err, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  if (c->c_fresh == 0) {
    idsa_event_copy(c->c_internal, c->c_template);
    idsa_scheme_verror_system(c->c_internal, err, s, ap);
  }

  c->c_fresh = 1;
  va_end(ap);
}
*/

static void idsa_client_error_internal(IDSA_CONNECTION * c, char *s, ...)
{
  va_list ap;

  va_start(ap, s);

  if (c->c_fresh == 0) {
    idsa_event_copy(c->c_internal, c->c_template);
    idsa_scheme_verror_internal(c->c_internal, s, ap);
  }

  c->c_fresh = 1;
  va_end(ap);
}

/* profiling stuff **********************************************************/

#ifdef WANTS_PROF
int idsa_prof(IDSA_CONNECTION * c, FILE * fp)
{

  if (c->c_profnum > 0) {
    fprintf(fp, "lib %ld/%d=%ld, system %ld/%d=%ld, wall %ld/%d=%ld\n", c->c_libtime, c->c_profnum, c->c_libtime / c->c_profnum, c->c_systime, c->c_profnum, c->c_systime / c->c_profnum, c->c_waltime, c->c_profnum, c->c_waltime / c->c_profnum);
  } else {
    fprintf(fp, "no events\n");
  }

  return 0;
}
#endif
