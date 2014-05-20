#ifndef _IDSA_H_
#define _IDSA_H_

/* hopefully fixed API */

#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

/* maximum values */
#define IDSA_M_NAME        28	/* longest unit name */
#define IDSA_M_SADDR      128	/* longest sockaddr_??   can be increased to M_LONG */
#define IDSA_M_STRING     128	/* longest string:       can be increased to M_LONG */
#define IDSA_M_FILE       128	/* longest file:         can be increased to M_LONG */
#define IDSA_M_LONG      1024	/* longest unit payload: upper limit on string/file size */
#define IDSA_M_MESSAGE   4096	/* longest event:        upper limit on anything */

#define IDSA_T_NULL    0	/* no type */
#define IDSA_T_STRING  1	/* 128 char string */
#define IDSA_T_INT     2	/* generic integer */
#define IDSA_T_UID     3	/* uid */
#define IDSA_T_GID     4	/* gid */
#define IDSA_T_PID     5	/* pid */
#define IDSA_T_TIME    6	/* time */
#define IDSA_T_FLAG    7	/* boolean */
#define IDSA_T_RISK    8	/* risk range */
#define IDSA_T_ERRNO   9	/* unix errno */
#define IDSA_T_HOST    10	/* 128 char net/host name */
#define IDSA_T_IP4ADDR 11	/* IPv4 + mask */
#define IDSA_T_ADDR    IDSA_T_IP4ADDR
#define IDSA_T_IPPORT  12	/* protocol/service */
#define IDSA_T_PORT    IDSA_T_IPPORT
#define IDSA_T_FILE    13	/* file (128 chars) */
#define IDSA_T_SADDR   14	/* socket address (not yet implemented) */
#define IDSA_M_TYPES   15	/* largest type + 1 */

/* structures you should not look into ************************************* */

#ifdef __cplusplus
extern "C" {
#endif
  struct idsa_unit;
  typedef struct idsa_unit IDSA_UNIT;

  struct idsa_event;
  typedef struct idsa_event IDSA_EVENT;

  struct idsa_connection;
  typedef struct idsa_connection IDSA_CONNECTION;

/* session setup *********************************************************** */

#define IDSA_F_FAILOPEN   0x0001	/* always allow if other side broken */
#define IDSA_F_KEEP       0x0002	/* don't delete IDSA_EVENT within idsa_log */
#define IDSA_F_ENV        0x0004	/* get location of socket from environment */
#define IDSA_F_SIGPIPE    0x0008	/* do not do a signal(SIGPIPE, SIG_IGN) - no longer used */
#define IDSA_F_UPLOAD     0x0010	/* enable client side code */
#define IDSA_F_TIMEOUT    0x0020	/* do not block indefinitely if server has gone bad */
#define IDSA_F_NOBACKOFF  0x0040	/* always retry */

  IDSA_CONNECTION *idsa_open(char *name, char *credential, int flags);
  int idsa_close(IDSA_CONNECTION * c);
  int idsa_reset(IDSA_CONNECTION * c);

/* event setup ************************************************************* */

  IDSA_EVENT *idsa_event(IDSA_CONNECTION * c);	/* get event */
  void idsa_template(IDSA_CONNECTION * c, IDSA_EVENT * e);	/* use e as template */
  void idsa_free(IDSA_CONNECTION * c, IDSA_EVENT * e);	/* needs only be called if F_KEEP set */

/* one line usage ********************************************************** */

  int idsa_scan(IDSA_CONNECTION * c, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...);
  int idsa_set(IDSA_CONNECTION * c, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...);

/* fill in details ********************************************************* */

/* units which should normally be set */
  int idsa_name(IDSA_EVENT * e, char *n);
  int idsa_scheme(IDSA_EVENT * e, char *n);
  int idsa_service(IDSA_EVENT * e, char *n);
  int idsa_risks(IDSA_EVENT * e, int f, unsigned a, unsigned c, unsigned i);
  int idsa_honour(IDSA_EVENT * e, int f);
#define idsa_honor idsa_honour

/* usually no point in modifying these units */
  int idsa_pid(IDSA_EVENT * e, pid_t p);
  int idsa_uid(IDSA_EVENT * e, uid_t u);
  int idsa_gid(IDSA_EVENT * e, gid_t g);
  int idsa_time(IDSA_EVENT * e, time_t t);
  int idsa_host(IDSA_EVENT * e, char *h);

/* optional comment: describe event to human reading it */
  int idsa_comment(IDSA_EVENT * e, char *m, ...);

/* add your own units to an event */
  int idsa_add_printf(IDSA_EVENT * e, char *n, char *s, ...);
  int idsa_add_vprintf(IDSA_EVENT * e, char *n, char *s, va_list ap);
  int idsa_add_string(IDSA_EVENT * e, char *n, char *s);
  int idsa_add_integer(IDSA_EVENT * e, char *n, int i);
  int idsa_add_scan(IDSA_EVENT * e, char *n, unsigned int t, char *s);
  int idsa_add_set(IDSA_EVENT * e, char *n, unsigned int t, void *p);
  int idsa_add_unit(IDSA_EVENT * e, IDSA_UNIT * u);

/* risk / cost defines **************************************************** */

  unsigned int idsa_risk_make(double severity, double confidence);
  double idsa_risk_severity(unsigned int risk);
  double idsa_risk_confidence(unsigned int risk);

#define IDSA_R_TOTAL       idsa_risk_make(1.000,0.990)
#define IDSA_R_PARTIAL     idsa_risk_make(0.500,0.750)
#define IDSA_R_MINOR       idsa_risk_make(0.250,0.875)
#define IDSA_R_NONE        idsa_risk_make(0.000,0.990)
#define IDSA_R_UNKNOWN     idsa_risk_make(0.000,0.000)
#define IDSA_R_SUCCESS     idsa_risk_make(-1.00,0.990)

/* for cases where user does not wish to supply a risks assessment */
#define IDSA_R_DECLINE     IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN

/* log event and get at results ******************************************** */

#define IDSA_L_DENY       0x01	/* event is disallowed */
#define IDSA_L_ALLOW      0x00	/* event is permitted */
#define IDSA_L_OK         IDSA_L_ALLOW
#define IDSA_L_FORWARD    0x02	/* event forwarded to main logger (unused) */

  int idsa_log(IDSA_CONNECTION * c, IDSA_EVENT * e);

/* get at error */
  int idsa_error(IDSA_CONNECTION * c);

/* get reasons for denying / allowing (may return NULL) */
  char *idsa_reason(IDSA_CONNECTION * c);

/* provide a syslog analog ************************************************* */

  void idsa_syslog(IDSA_CONNECTION * c, int pri, char *fmt, ...);
  void idsa_vsyslog(IDSA_CONNECTION * c, int pri, char *fmt, va_list args);
  int idsa_event_syslog(IDSA_EVENT * e, int pri, char *msg);

/* provide version information ********************************************* */

  char *idsa_version_runtime();
#define idsa_version_compile() "unknown"

#ifdef __cplusplus
}
#endif
#endif
