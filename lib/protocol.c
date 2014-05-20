

/****************************************************************************/
/*                                                                          */
/*  Handle the request/reply protocol, with the odd name resolution         */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/utsname.h>
#include <sys/types.h>

#include <idsa_internal.h>

/* the version of indent I am using has no idea about structure inits */

struct idsa_reserved {
  char r_name[IDSA_M_NAME];
  unsigned int r_type;
  unsigned int r_request;
  unsigned int r_reply;
};

static struct idsa_reserved idsa_res_tab[IDSA_M_RESERVED] = {
  [IDSA_Q_PID] = {"pid", IDSA_T_PID, 0, IDSA_M_UNKNOWN},
  [IDSA_Q_UID] = {"uid", IDSA_T_UID, 1, IDSA_M_UNKNOWN},
  [IDSA_Q_GID] = {"gid", IDSA_T_GID, 2, IDSA_M_UNKNOWN},
  [IDSA_Q_TIME] = {"time", IDSA_T_TIME, 3, IDSA_M_UNKNOWN},
  [IDSA_Q_SERVICE] = {"service", IDSA_T_STRING, 4, IDSA_M_UNKNOWN},
  [IDSA_Q_HOST] = {"host", IDSA_T_HOST, 5, IDSA_M_UNKNOWN},
  [IDSA_Q_NAME] = {"name", IDSA_T_STRING, 6, IDSA_M_UNKNOWN},
  [IDSA_Q_SCHEME] = {"scheme", IDSA_T_STRING, 7, IDSA_M_UNKNOWN},
  [IDSA_Q_HONOUR] = {"honour", IDSA_T_FLAG, 8, IDSA_M_UNKNOWN},
  [IDSA_Q_ARISK] = {"arisk", IDSA_T_RISK, 9, IDSA_M_UNKNOWN},
  [IDSA_Q_CRISK] = {"crisk", IDSA_T_RISK, 10, IDSA_M_UNKNOWN},
  [IDSA_Q_IRISK] = {"irisk", IDSA_T_RISK, 11, IDSA_M_UNKNOWN},
  [IDSA_P_DENY] = {"deny", IDSA_T_FLAG, IDSA_M_UNKNOWN, 0},
  [IDSA_O_REPEAT] = {"repeat", IDSA_T_INT, IDSA_M_UNKNOWN, 1},
  [IDSA_O_REASON] = {"reason", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_JOB] = {"job", IDSA_T_INT, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_COMMENT] = {"comment", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_PRERULE] = {"prerule", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_PREFILE] = {"prefile", IDSA_T_FILE, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_FAILRULE] = {"failrule", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_FAILFILE] = {"failfile", IDSA_T_FILE, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_AUTORULE] = {"autorule", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_AUTOFILE] = {"autofile", IDSA_T_FILE, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_BOTHRULE] = {"bothrule", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_BOTHFILE] = {"bothfile", IDSA_T_FILE, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_SLEEP] = {"sleep", IDSA_T_INT, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_STOP] = {"stop", IDSA_T_FLAG, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN},
  [IDSA_O_ENV] = {"env", IDSA_T_STRING, IDSA_M_UNKNOWN, IDSA_M_UNKNOWN}
};

/* reverse lookups */

static unsigned int idsa_request_table[IDSA_M_REQUEST] = {
  IDSA_Q_PID, IDSA_Q_UID, IDSA_Q_GID, IDSA_Q_TIME, IDSA_Q_SERVICE,
  IDSA_Q_HOST, IDSA_Q_NAME, IDSA_Q_SCHEME, IDSA_Q_HONOUR, IDSA_Q_ARISK,
  IDSA_Q_CRISK, IDSA_Q_IRISK
};

static unsigned int idsa_reply_table[IDSA_M_REPLY] = {
  IDSA_P_DENY
};

/***********************************************************************/

unsigned int idsa_resolve_request(unsigned int n)
{
  if (n < IDSA_M_RESERVED) {
    return idsa_res_tab[n].r_request;
  } else {
    return IDSA_M_UNKNOWN;
  }
}

unsigned int idsa_resolve_reply(unsigned int n)
{
  if (n < IDSA_M_RESERVED) {
    return idsa_res_tab[n].r_reply;
  } else {
    return IDSA_M_UNKNOWN;
  }
}

unsigned int idsa_resolve_code(char *n)
{
  unsigned int result;

  if (n == NULL) {
    return IDSA_M_UNKNOWN;
  }

  for (result = 0; result < IDSA_M_RESERVED; result++) {
    if (strcmp(idsa_res_tab[result].r_name, n) == 0) {
#ifdef DEBUG
      fprintf(stderr, "idsa_solve_code(): <%s> has code 0x%04x\n", n, result);
#endif
      return result;
    }
  }

  return IDSA_M_UNKNOWN;
}

char *idsa_resolve_name(unsigned int c)
{
  if (c < IDSA_M_RESERVED) {
    return idsa_res_tab[c].r_name;
  } else {
    return NULL;
  }
}

unsigned int idsa_resolve_type(unsigned int c, char *n)
{
  unsigned int i;

  if (c < IDSA_M_RESERVED) {
    return idsa_res_tab[c].r_type;
  }

  if (!n) {
    return IDSA_T_NULL;
  }

  for (i = 0; i < IDSA_M_RESERVED; i++) {
    if (!strcmp(idsa_res_tab[i].r_name, n)) {
#ifdef DEBUG
      fprintf(stderr, "idsa_solve_type(): <%s> has type 0x%04x\n", n, idsa_res_tab[i].r_type);
#endif
      return idsa_res_tab[i].r_type;
    }
  }

  return IDSA_T_NULL;
}

/****************************************************************************/

unsigned int idsa_request_count()
{
  return IDSA_M_REQUEST;
}

unsigned int idsa_reply_count()
{
  return IDSA_M_REPLY;
}

/****************************************************************************/

static int idsa_any_init(IDSA_EVENT * event, unsigned int *table, unsigned int size)
{
  int result = 0;
  IDSA_UNIT *u;
  unsigned int i, j;

  j = 0;

  for (i = 0; i < size; i++) {
    j = table[i];
#ifdef DEBUG
    fprintf(stderr, "idsa_any_init(): name[[%d]=%d]=<%s>\n", i, j, idsa_res_tab[j].r_name);
#endif
    u = idsa_event_scanappend(event, idsa_res_tab[j].r_name, idsa_res_tab[j].r_type, NULL);
    if (u) {
#ifdef DEBUG
      fprintf(stderr, "idsa_any_init(): set up reserved <%s> to <%p>\n", idsa_unit_name_get(u), u);
#endif
    } else {
      result++;
    }
  }

  return result;
}

/****************************************************************************/
/* Does       : Fill in reasonable defaults for a request event             */

int idsa_request_init(IDSA_EVENT * e, char *service, char *scheme, char *name)
{
  int result = 0;
  struct utsname ut;

  /* format event and create reserved fields */
  idsa_event_clear(e, IDSA_MAGIC_REQUEST);

  /* fill in the required fields */
  result += idsa_any_init(e, idsa_request_table, IDSA_M_REQUEST);

  result += idsa_risks(e, 0, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN);

  /* put sensible defaults into the required fields */
  result += idsa_service(e, service);
  result += idsa_scheme(e, scheme);
  result += idsa_name(e, name);
  result += idsa_host(e, uname(&ut) ? "localhost" : ut.nodename);
  result += idsa_uid(e, getuid());
  result += idsa_gid(e, getgid());
  result += idsa_pid(e, getpid());
  result += idsa_time(e, time(NULL));

#ifdef DEBUG
  idsa_event_dump(e, stderr);
#endif

  return result;
}

/****************************************************************************/
/* Does       : Generates the default reply - note the default allow        */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_reply_init(IDSA_EVENT * e)
{
  int result = 0;

  idsa_event_clear(e, IDSA_MAGIC_REPLY);

  /* fill in the required fields */
  result += idsa_any_init(e, idsa_reply_table, IDSA_M_REPLY);

  result += idsa_reply_allow(e);

#ifdef DEBUG
  idsa_event_dump(e, stderr);
#endif

  return result;
}

/****************************************************************************/

static int idsa_any_check(IDSA_EVENT * event, unsigned int *table, unsigned int size)
{
  IDSA_UNIT *u;
  unsigned int i, j;

  for (i = 0; i < size; i++) {
    j = table[i];
    u = idsa_event_unitbynumber(event, i);
    if (u) {
      if (idsa_res_tab[j].r_type != idsa_unit_type(u)) {
#ifdef DEBUG
	fprintf(stderr, "idsa_any_check(): unit[%d].type=%02x != table[%d]=%02x\n", i, idsa_unit_type(u), j, idsa_res_tab[j].r_type);
#endif
	return 1;
      }
    } else {
      return 1;
    }
  }

  return 0;
}

/****************************************************************************/
/* Does       : Eyeballs event, attempts to overwrite as much as possible   */
/*              to make it consistent                                       */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_request_check(IDSA_EVENT * e)
{
  if (e->e_magic != IDSA_MAGIC_REQUEST) {
#ifdef DEBUG
    fprintf(stderr, "idsa_request_check(): bad magic\n");
#endif
    return 1;
  }

  if (idsa_event_check(e)) {
#ifdef DEBUG
    fprintf(stderr, "idsa_request_check(): event check failed\n");
#endif
    return 1;
  }

  if (IDSA_M_REQUEST > e->e_count) {
#ifdef DEBUG
    fprintf(stderr, "idsa_request_check(): too few units in request event\n");
#endif
    return 1;
  }

  return idsa_any_check(e, idsa_request_table, IDSA_M_REQUEST);
}

/****************************************************************************/
/* Does       : Establish if reply is valid                                 */
/* Returns    : zero on success, nonzero otherwise                          */

int idsa_reply_check(IDSA_EVENT * e)
{
  if (e->e_magic != IDSA_MAGIC_REPLY) {
#ifdef DEBUG
    fprintf(stderr, "idsa_reply_check(): bad magic\n");
#endif
    return 1;
  }

  if (idsa_event_check(e)) {
    return 1;
  }

  if (IDSA_M_REPLY > e->e_count) {
#ifdef DEBUG
    fprintf(stderr, "idsa_reply_check(): too few units in reply event\n");
#endif
    return 1;
  }

  return idsa_any_check(e, idsa_reply_table, IDSA_M_REPLY);
}

/****************************************************************************/

IDSA_UNIT *idsa_request_get(IDSA_EVENT * e, unsigned int c, char *n)
{
  if ((c < IDSA_M_RESERVED)
      && (idsa_res_tab[c].r_request < IDSA_M_REQUEST)) {
    return idsa_event_unitbynumber(e, idsa_res_tab[c].r_request);
  } else if (n) {
    return idsa_event_unitbyname(e, n);
  } else {
    return NULL;
  }
}

/****************************************************************************/

IDSA_UNIT *idsa_reply_get(IDSA_EVENT * e, unsigned int c, char *n)
{
  if ((c < IDSA_M_RESERVED) && (idsa_res_tab[c].r_reply < IDSA_M_REPLY)) {
    return idsa_event_unitbynumber(e, idsa_res_tab[c].r_reply);
  } else if (n) {
    return idsa_event_unitbyname(e, n);
  } else {
    return NULL;
  }
}

/****************************************************************************/

/****************************************************************************/
/* Does       : Set name, scheme, risk and additional values in one go      */

int idsa_request_set(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...)
{
  int result;
  va_list ap;

  va_start(ap, ir);

  result = idsa_request_vset(e, n, s, f, ar, cr, ir, ap);

  va_end(ap);

  return result;
}

int idsa_request_vset(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, va_list ap)
{
  char *k;
  void *v;
  unsigned int t;
  int result = 0;

  if (!(idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_NAME].r_request, n)
	&& idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_SCHEME].r_request, s)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_HONOUR].r_request, &f)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_ARISK].r_request, &ar)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_CRISK].r_request, &cr)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_IRISK].r_request, &ir))) {
#ifdef DEBUG
    fprintf(stderr, "idsa_request_vset(): unable to set required fields\n");
#endif
    result++;
  }
  k = va_arg(ap, char *);
  while (k) {
    t = va_arg(ap, unsigned int);
    v = va_arg(ap, void *);

    if (idsa_event_setappend(e, k, t, v) == NULL) {
#ifdef DEBUG
      fprintf(stderr, "idsa_request_vset(): unable to append field <%s>\n", k);
#endif
      result++;
    }
    k = va_arg(ap, char *);
  }

  return result;
}

/****************************************************************************/
/* Does       : Scan name, scheme, risk and additional values in one go     */

int idsa_request_scan(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...)
{
  int result;
  va_list ap;

  va_start(ap, ir);

  result = idsa_request_vscan(e, n, s, f, ar, cr, ir, ap);

  va_end(ap);

  return result;
}

int idsa_request_vscan(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, va_list ap)
{
  char *k;
  char *v;
  unsigned int t;
  int result = 0;

  if (!(idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_NAME].r_request, n)
	&& idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_SCHEME].r_request, s)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_HONOUR].r_request, &f)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_ARISK].r_request, &ar)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_CRISK].r_request, &cr)
	&& idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_IRISK].r_request, &ir))) {
#ifdef DEBUG
    fprintf(stderr, "idsa_event_vscan(): unable to set required fields\n");
#endif
    result++;
  }
  k = va_arg(ap, char *);
  while (k) {
    t = va_arg(ap, unsigned int);
    v = va_arg(ap, char *);

    if (idsa_event_scanappend(e, k, t, v) == NULL) {
#ifdef DEBUG
      fprintf(stderr, "idsa_event_vscan(): unable to append field <%s>\n", k);
#endif
      result++;
    }
    k = va_arg(ap, char *);
  }

  return result;
}

/****************************************************************************/
/* Does       : Sets process id of event                                    */

int idsa_request_pid(IDSA_EVENT * e, pid_t p)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_PID].r_request, &p)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets owner of event                                         */

int idsa_request_uid(IDSA_EVENT * e, uid_t u)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_UID].r_request, &u)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets group owner of event                                   */

int idsa_request_gid(IDSA_EVENT * e, gid_t g)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_GID].r_request, &g)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets event timestamp                                        */
/* Notes      : Pointless, log will add its own                             */

int idsa_request_time(IDSA_EVENT * e, time_t t)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_TIME].r_request, &t)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets hostname for this event                                */

int idsa_request_host(IDSA_EVENT * e, char *h)
{
  if (idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_HOST].r_request, h)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets name field for event                                   */

int idsa_request_name(IDSA_EVENT * e, char *n)
{
  if (idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_NAME].r_request, n)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets scheme/namespace for event                             */

int idsa_request_scheme(IDSA_EVENT * e, char *s)
{
  if (idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_SCHEME].r_request, s)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets service name for event                                 */

int idsa_request_service(IDSA_EVENT * e, char *s)
{
  if (idsa_event_scanbynumber(e, idsa_res_tab[IDSA_Q_SERVICE].r_request, s)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets risk rating of event                                   */

int idsa_request_risks(IDSA_EVENT * e, int f, unsigned a, unsigned c, unsigned i)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_HONOUR].r_request, &f)
      && idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_ARISK].r_request, &a)
      && idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_CRISK].r_request, &c)
      && idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_IRISK].r_request, &i)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/
/* Does       : Sets flag indicating if a deny will be honoured             */

int idsa_request_honour(IDSA_EVENT * e, int f)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_Q_HONOUR].r_request, &f)) {
    return 0;
  } else {
    return 1;
  }
}

/****************************************************************************/

int idsa_reply_allow(IDSA_EVENT * e)
{
  int deny = 0;

  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_P_DENY].r_reply, &deny)) {
    return 0;
  } else {
    return 1;
  }
}

int idsa_reply_deny(IDSA_EVENT * e)
{
  int deny = 1;

  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_P_DENY].r_reply, &deny)) {
    return 0;
    return 0;
  } else {
    return 1;
  }
}

int idsa_reply_result(IDSA_EVENT * e)
{
  int result = IDSA_L_DENY;
  IDSA_UNIT *u;

  u = idsa_event_unitbynumber(e, idsa_res_tab[IDSA_P_DENY].r_reply);
  if (u) {
    idsa_unit_get(u, &result, sizeof(int));
  }

  return result;
}

int idsa_reply_repeat(IDSA_EVENT * e, int repeat)
{
  if (idsa_event_setbynumber(e, idsa_res_tab[IDSA_O_REPEAT].r_reply, &repeat)) {
    return 0;
  } else {
    return 1;
  }
}
