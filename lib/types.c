
/****************************************************************************/
/*                                                                          */
/*  Functions to scan (parse), print (display in human readable format),    */
/*  set (modify in dangerous ways), check integrity and compare various     */
/*  data types. At some stage this should be improved to have proper IO     */
/*  functions for each unit - instead of the half-baked scan and print.     */
/*  Problem is that types which use symbolic names are not chroot()         */
/*  safe - they require support files in jail.                              */
/*                                                                          */
/****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <idsa_internal.h>

#define ESCAPE_UNIX 1
#define ESCAPE_XML  2

/* string handler ******************************************************* */

static int idsa_string_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  int result;

  result = strncmp(a->u_ptr, b->u_ptr, idsa_type_size(a->u_type));

  if (result < 0) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (result > 0) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

#ifdef DEBUG
  fprintf(stderr, "compare_string(): comparing of <%s> against <%s>\n", a->u_ptr, b->u_ptr);
#endif

  return result;
}

static int idsa_string_check(IDSA_UNIT * u)
{
  u->u_ptr[idsa_type_size(u->u_type) - 1] = '\0';
  return 0;
}

static int idsa_string_scan(IDSA_UNIT * u, char *s)
{
  int i, m;
  int result = 0;

  i = strlen(s);
  m = idsa_type_size(u->u_type);

  if (i > (m - 1)) {
    result = 1;			/* string too long, but we try our best */
    strncpy(u->u_ptr, s, m - 4);
    strncpy(u->u_ptr + (m - 5), "...", 4);
    i = m - 1;
  } else {
    strncpy(u->u_ptr, s, i);
  }
  u->u_ptr[i] = '\0';

  return result;
}

static int idsa_string_print(IDSA_UNIT * u, char *s, int l, int m)
{
  int i;

  i = strlen(u->u_ptr);
  if (l < i) {
    memcpy(s, u->u_ptr, l);	/* feeble best effort */
    return -1;
  }

  memcpy(s, u->u_ptr, i);
  switch (m) {
  case ESCAPE_UNIX:
    return idsa_escape_unix(s, i, l);
  case ESCAPE_XML:
    return idsa_escape_xml(s, i, l);
  default:
    return i;
  }
}

static int idsa_string_set(IDSA_UNIT * u, void *p)
{
  return idsa_string_scan(u, p);
}

static int idsa_string_get(IDSA_UNIT * u, void *p, int l)
{
  return idsa_string_print(u, p, l, 0);
}

/* integer handler ****************************************************** */

static int idsa_int_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  unsigned int x, y;
  int result;

  memcpy(&x, a->u_ptr, sizeof(int));
  memcpy(&y, b->u_ptr, sizeof(int));

  if (x < y) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x > y) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

  return result;
}

static int idsa_int_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(int));

  return 0;
}

static int idsa_int_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(int)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(int));
    return sizeof(int);
  }
}

static int idsa_int_scan(IDSA_UNIT * u, char *s)
{
  unsigned int i;

  if (isdigit(s[0])) {
    i = atoi(s);
    memcpy(u->u_ptr, &i, sizeof(int));
    return 0;
  } else {
    return -1;
  }
}

static int idsa_int_print(IDSA_UNIT * u, char *s, int l, int m)
{
  unsigned int i;
  int x;

  memcpy(&i, u->u_ptr, sizeof(int));

  x = snprintf(s, l, "%u", i);
  return (x > l) ? (-1) : x;
}

/* uid lookup: ********************************************************** */

static int idsa_uid_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  uid_t x, y;
  int result;

  memcpy(&x, a->u_ptr, sizeof(uid_t));
  memcpy(&y, b->u_ptr, sizeof(uid_t));

  if (x < y) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x > y) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

  return result;
}

static int idsa_uid_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(uid_t));

  return 0;
}

static int idsa_uid_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(uid_t)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(uid_t));
    return sizeof(uid_t);
  }
}

static int idsa_uid_scan(IDSA_UNIT * u, char *s)
{
  struct passwd *pw;
  uid_t i;

  if (isdigit(s[0])) {
    i = atoi(s);
    memcpy(u->u_ptr, &i, sizeof(uid_t));
    return 0;
  } else {
    pw = getpwnam(s);
    if (pw) {
      memcpy(u->u_ptr, &(pw->pw_uid), sizeof(uid_t));
      return 0;
    } else {
      return 1;
    }
  }

  return 1;
}

static int idsa_uid_print(IDSA_UNIT * u, char *s, int l, int m)
{
  uid_t i;
  int x;

  memcpy(&i, u->u_ptr, sizeof(uid_t));

  x = snprintf(s, l, "%u", i);
  return (x > l) ? (-1) : x;
}

/* gid lookup: ********************************************************** */

static int idsa_gid_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  gid_t x, y;
  int result;

  memcpy(&x, a->u_ptr, sizeof(gid_t));
  memcpy(&y, b->u_ptr, sizeof(gid_t));

  if (x < y) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x > y) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

  return result;
}

static int idsa_gid_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(gid_t));

  return 0;
}

static int idsa_gid_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(gid_t)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(gid_t));
    return sizeof(gid_t);
  }
}

static int idsa_gid_scan(IDSA_UNIT * u, char *s)
{
  struct group *gr;
  gid_t i;

  if (isdigit(s[0])) {
    i = atoi(s);
    memcpy(u->u_ptr, &i, sizeof(gid_t));
    return 0;
  } else {
    gr = getgrnam(s);
    if (gr) {
      memcpy(u->u_ptr, &(gr->gr_gid), sizeof(gid_t));
      return 0;
    } else {
      return 1;
    }
  }
}

static int idsa_gid_print(IDSA_UNIT * u, char *s, int l, int m)
{
  gid_t i;
  int x;

  memcpy(&i, u->u_ptr, sizeof(gid_t));

  x = snprintf(s, l, "%u", i);
  return (x > l) ? (-1) : x;
}

/* pid lookup: ********************************************************** */

static int idsa_pid_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  pid_t x, y;
  int result;

  memcpy(&x, a->u_ptr, sizeof(pid_t));
  memcpy(&y, b->u_ptr, sizeof(pid_t));

  if (x < y) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x > y) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

  return result;
}

static int idsa_pid_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(pid_t));

  return 0;
}

static int idsa_pid_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(pid_t)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(pid_t));
    return sizeof(pid_t);
  }
}

static int idsa_pid_scan(IDSA_UNIT * u, char *s)
{
  pid_t i;

  if (isdigit(s[0])) {
    i = atoi(s);
    memcpy(u->u_ptr, &i, sizeof(pid_t));
    return 0;
  } else {
    return -1;
  }
}

static int idsa_pid_print(IDSA_UNIT * u, char *s, int l, int m)
{
  pid_t i;
  int x;

  memcpy(&i, u->u_ptr, sizeof(pid_t));

  x = snprintf(s, l, "%u", i);
  return (x > l) ? (-1) : x;
}

/* time handler (to be done properly) *********************************** */

static int idsa_time_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  time_t x, y;
  int result;

  memcpy(&x, a->u_ptr, sizeof(time_t));
  memcpy(&y, b->u_ptr, sizeof(time_t));

  if (x < y) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x > y) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  }

  return result;
}

static int idsa_time_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(time_t));

  return 0;
}

static int idsa_time_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(time_t)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(time_t));
    return sizeof(time_t);
  }
}

static int idsa_time_scan(IDSA_UNIT * u, char *s)
{
  time_t i;

  if (isdigit(s[0])) {
    i = atoi(s);
    memcpy(u->u_ptr, &i, sizeof(time_t));
    return 0;
  } else {
    return -1;
  }
}

static int idsa_time_print_rfc1123_utc(time_t t, char *s, int l)
{
  struct tm *tp;
#ifdef SAFE
  char saves[30];
#else
  static time_t savet = 0;
  static char saves[30] = "Thu, 01 Jan 1970 00:00:00 GMT";
#endif

  const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
    "Oct", "Nov", "Dec"
  };
  const char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

  if (l < 29) {
    return -1;
  } else {
#ifndef SAFE
    if (t != savet) {
#endif
      tp = gmtime(&t);
      snprintf(saves, 30, "%s, %2d %s %04d %02d:%02d:%02d GMT", days[tp->tm_wday % 7], tp->tm_mday, months[tp->tm_mon % 12], tp->tm_year + 1900, tp->tm_hour, tp->tm_min, tp->tm_sec);
      saves[29] = '\0';
#ifndef SAFE
      savet = t;
    }
#endif
#ifdef DEBUG
    fprintf(stderr, "idsa_time_print_syslog(): new time is <%s>\n", saves);
#endif
    memcpy(s, saves, 29);
    return 29;
  }
}

static int idsa_time_print_colon_utc(time_t t, char *s, int l)
{
  struct tm *tp;
#ifdef SAFE
  char saves[20];
#else
  static time_t savet = 0;
  static char saves[20] = "1970:01:01:00:00:00";
#endif

#ifdef DEBUG
  fprintf(stderr, "idsa_time_print_colon(): previous time is <%s>\n", saves);
#endif

  if (l < 20) {
    return -1;
  } else {
#ifndef SAFE
    if (t != savet) {
#endif
      tp = gmtime(&t);
      snprintf(saves, 20, "%04d:%02d:%02d:%02d:%02d:%02d", tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
      saves[19] = '\0';
#ifndef SAFE
      savet = t;
    }
#endif
#ifdef DEBUG
    fprintf(stderr, "idsa_time_print_colon(): new time is <%s>\n", saves);
#endif
    memcpy(s, saves, 19);
    return 19;
  }
}


static int idsa_time_print_rfc3339_utc(time_t t, char *s, int l)
{

  struct tm *tp;
#ifdef SAFE
  char saves[21];
#else
  static time_t savet = 0;
  static char saves[21] = "1970-01-01T00:00:00Z";
#endif

#ifdef DEBUG
  fprintf(stderr, "idsa_time_print_iso_subset(): previous time is <%s>\n", saves);
#endif

  if (l < 20) {
    return -1;
  } else {
#ifndef SAFE
    if (t != savet) {
#endif
      tp = gmtime(&t);
      snprintf(saves, 21, "%04d-%02d-%02dT%02d:%02d:%02dZ", tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
      saves[20] = '\0';
#ifndef SAFE
      savet = t;
    }
#endif
#ifdef DEBUG
    fprintf(stderr, "idsa_time_print_iso_subset(): new time is <%s>\n", saves);
#endif
    memcpy(s, saves, 20);
    return 20;
  }
}

static int idsa_time_print_syslog_local(time_t t, char *s, int l)
{
  struct tm *tp;
#ifdef SAFE
  char saves[16];
#else
  static time_t savet = 0;
  static char saves[16] = "Jan  1 00:00:00";
#endif

  const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
    "Oct", "Nov", "Dec"
  };

#ifdef DEBUG
  fprintf(stderr, "idsa_time_print_syslog(): previous time is <%s>\n", saves);
#endif

  if (l < 16) {
    return -1;
  } else {
#ifndef SAFE
    if ((t == 0) || (t != savet)) {
#endif
      tp = localtime(&t);
      snprintf(saves, 16, "%s %2d %02d:%02d:%02d", months[tp->tm_mon % 12], tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
#ifndef SAFE
      savet = t;
    }
#endif
#ifdef DEBUG
    fprintf(stderr, "idsa_time_print_syslog(): new time is <%s>\n", saves);
#endif
    memcpy(s, saves, 15);
    return 15;
  }
}

/*
Difference in seconds between 1970 and 1900. 
Derrivation: days: (i=1900; while [ $i -lt 1970 ]; do cal $i | grep -v $i | tr -d [A-Za-z] | tr '\n' ' '  | tr -s \  ;i=$[i+1]; done) | wc -w
FIXME: Correct for leap seconds, if any 
*/

#define IDSA_TIME_DELTA  2208988800U

static int idsa_time_print_broken_ntp(time_t t, char *s, int l)
{
  int x;
  unsigned int u;

  u = IDSA_TIME_DELTA + t;
  x = snprintf(s, l, "0x%08x.0x80000000", u);
  return (x > l) ? (-1) : x;
}

static int idsa_time_print_default(time_t t, char *s, int l)
{
  int x;
  x = snprintf(s, l, "%lu", t);
  return (x > l) ? (-1) : x;
}

static int idsa_time_print(IDSA_UNIT * u, char *s, int l, int m)
{
  time_t t;

  memcpy(&t, u->u_ptr, sizeof(time_t));

  switch (m) {
  case 100:
    return idsa_time_print_syslog_local(t, s, l);
  case 101:
    return idsa_time_print_rfc1123_utc(t, s, l);
  case 102:
    return idsa_time_print_colon_utc(t, s, l);
  case 103:
    return idsa_time_print_rfc3339_utc(t, s, l);
  case 104:
    return idsa_time_print_broken_ntp(t, s, l);
  default:
    return idsa_time_print_default(t, s, l);
  }

  return -1;
}

/* flag handler (nice and simple) *************************************** */

static int idsa_flag_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  unsigned int x, y;

  memcpy(&x, a->u_ptr, sizeof(int));
  memcpy(&y, b->u_ptr, sizeof(int));

  if (x) {
    if (y) {
      return IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
    } else {
      return IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
    }
  } else {
    if (y) {
      return IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
    } else {
      return IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
    }
  }
}

static int idsa_flag_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(int));

  return 0;
}

static int idsa_flag_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(unsigned int)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(unsigned int));
    return sizeof(unsigned int);
  }
}

static int idsa_flag_scan(IDSA_UNIT * u, char *s)
{
  unsigned int i;

  if (s[0] == '0' || s[0] == 'f' || s[0] == 'F') {
    i = 0;
  } else {
    i = 1;
  }
  memcpy(u->u_ptr, &i, sizeof(int));

  return 0;
}

static int idsa_flag_print(IDSA_UNIT * u, char *s, int l, int m)
{
  unsigned int i;
  int x;

  memcpy(&i, u->u_ptr, sizeof(int));

  if (l > 0) {
    switch (m) {
    case 100:
      x = snprintf(s, l, "%s", i ? "true" : "false");
      return (x > l) ? (-1) : x;
    default:
      s[0] = i ? '1' : '0';
      return 1;
    }
  } else {
    return -1;
  }
}

/* risk handler (not simple) ******************************************** */

static int idsa_risk_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  unsigned int x, y;

  memcpy(&x, a->u_ptr, sizeof(int));
  memcpy(&y, b->u_ptr, sizeof(int));

  return idsa_risk_cmp(x, y);
}

/*
static int idsa_risk_check(IDSA_UNIT * u)
{
  return 0;
}
*/

static int idsa_risk_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, sizeof(int));

  return 0;
}

static int idsa_risk_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < sizeof(int)) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, sizeof(int));
    return sizeof(int);
  }
}

static int idsa_risk_scan(IDSA_UNIT * u, char *s)
{
  unsigned int x;

  x = idsa_risk_parse(s);

  memcpy(u->u_ptr, &x, sizeof(int));

  return 0;
}

static int idsa_risk_print(IDSA_UNIT * u, char *s, int l, int m)
{
  unsigned int x;
  int y;

  memcpy(&x, u->u_ptr, sizeof(int));

  y = idsa_risk_put(x, s, l);

  if (y != 0) {
    return -1;
  }

  return strlen(s);
}

/* errno handler ******************************************************** */

static int idsa_errno_print(IDSA_UNIT * u, char *s, int l, int m)
{
  int i, n;
  char *p;
  int x;

  memcpy(&i, u->u_ptr, sizeof(int));
  switch (m) {
  case 100:
    p = strerror(i);
    if (p) {
      n = strlen(p);
      if (n > l) {
	memcpy(s, p, l);
	return -1;
      } else {
	memcpy(s, p, n);
	return n;
      }
    } else {
      p[0] = '\0';
      return 0;
    }
    break;
  default:
    x = snprintf(s, l, "%u", i);
    return (x > l) ? (-1) : x;
    break;
  }

}

/* hostname handler (host.some.domain), stored in reverse order to ****** */
/* make matching of .domains easier ************************************* */

static int idsa_host_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  int result;
  int i, z;

  i = 0;
  z = idsa_type_size(a->u_type);
  while ((i < z) && (a->u_ptr[i] == b->u_ptr[i]) && (a->u_ptr[i] != '\0')) {
    i++;
  }

  if (a->u_ptr[i] == b->u_ptr[i]) {	/* both == '\0' */
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  } else {

    result = IDSA_COMPARE_DISJOINT;
    if (i > 0) {		/* check for trailing . for network match */
      if ((a->u_ptr[i] == '\0') || (b->u_ptr[i] == '\0')) {
	if ((b->u_ptr[i - 1] == '.')
	    && (a->u_ptr[i - 1] == b->u_ptr[i - 1])) {
	  result = IDSA_COMPARE_INTERSECT;
	}
      }
    }

    if (a->u_ptr[i] < b->u_ptr[i]) {
      result |= IDSA_COMPARE_LESS;
    } else {			/* a > b */
      result |= IDSA_COMPARE_MORE;
    }
  }

#ifdef DEBUG
  fprintf(stderr, "compare_host(): compare of <%s> against <%s> yields <%d>\n", a->u_ptr, b->u_ptr, result);
#endif

  return result;
}

static int idsa_host_check(IDSA_UNIT * u)
{
  u->u_ptr[idsa_type_size(u->u_type) - 1] = '\0';
  return 0;
}

static int idsa_host_scan(IDSA_UNIT * u, char *s)
{
  int i, j, m;
  int result = 0;

  i = strlen(s);
  m = idsa_type_size(u->u_type);

  if (i < m) {
    m = i;
  } else {
    m--;
    result = 1;
  }

  i--;
  j = 0;
  while (j < m) {
    u->u_ptr[j] = s[i];
    j++;
    i--;
  }
  u->u_ptr[j] = '\0';

  return result;
}

static int idsa_host_print(IDSA_UNIT * u, char *s, int l, int m)
{
  int i, j, result, z;

  i = 0;
  z = idsa_type_size(u->u_type);
  while ((i < z) && (u->u_ptr[i] != '\0')) {
    i++;
  }

  if (l < i) {
    return -1;
  }
#ifdef DEBUG
  fprintf(stderr, "print_host(): <%s:%d>\n", u->u_ptr, i);
#endif

  result = i;
  i--;

  j = 0;
  while (i >= 0) {
    s[j] = u->u_ptr[i];
    j++;
    i--;
  }

  switch (m) {
  case ESCAPE_UNIX:
    return idsa_escape_unix(s, result, l);
  case ESCAPE_XML:
    return idsa_escape_xml(s, result, l);
  default:
    return result;
  }

}

static int idsa_host_set(IDSA_UNIT * u, void *p)
{
  return idsa_host_scan(u, p);
}

static int idsa_host_get(IDSA_UNIT * u, void *p, int l)
{
  return idsa_host_print(u, p, l, 0);
}

/* inet ipv4 address handler. Internal storage representation is an ***** */
/* array of 2 integers, one for address, and one for (32-mask) ********** */

static int idsa_ip4addr_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  int result;
  unsigned long int p[2], q[2], m;

  memcpy(p, a->u_ptr, 2 * sizeof(long int));
  memcpy(q, b->u_ptr, 2 * sizeof(long int));
  if (p[1] > q[1]) {
    m = (0xffffffff << (p[1]));
  } else {
    m = (0xffffffff << (q[1]));
  }

  p[0] = (p[0] & m);
  q[0] = (q[0] & m);

  if (p[0] == q[0]) {
    if (p[1] == q[1]) {
      result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
    } else {
      result = IDSA_COMPARE_INTERSECT | (p[1] > q[1] ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS);
    }
  } else {
    result = IDSA_COMPARE_DISJOINT | (p[0] > q[0] ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS);
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_ip4addr_compare(): hostmask is <0x%08lx> bits, <0x%08lx?0x%08lx>, result <%d>\n", m, p[0], q[0], result);
#endif

  return result;
}

static int idsa_ip4addr_check(IDSA_UNIT * u)
{
  unsigned long int a[2];
  int result = 0;

  memcpy(a, u->u_ptr, 2 * sizeof(long int));
  if (a[1] > 32) {
    a[1] = 0;
    result++;
  }
  return result;
}

static int idsa_ip4addr_set(IDSA_UNIT * u, void *p)
{
  unsigned long int a[2];

  memcpy(a, p, sizeof(long int));
  a[1] = 0;

#ifdef DEBUG
  fprintf(stderr, "idsa_ip4addr_set(): 0x%08lx/%ld\n", a[0], a[1]);
#endif

  memcpy(u->u_ptr, a, 2 * sizeof(long int));

  return 0;
}

static int idsa_ip4addr_get(IDSA_UNIT * u, void *p, int l)
{
  unsigned long int a[2];

  memcpy(a, u->u_ptr, 2 * sizeof(long int));

#ifdef DEBUG
  fprintf(stderr, "idsa_ip4addr_get(): 0x%08lx/%ld\n", a[0], a[1]);
#endif

  if (l < sizeof(long int)) {
    return -1;
  } else {
    memcpy(p, a, sizeof(long int));
    return sizeof(long int);
  }
}

static int idsa_ip4addr_scan(IDSA_UNIT * u, char *s)
{
  struct in_addr d;
  int result;
  int i;
  unsigned long int a[2];
  char tmp[16];

  /* FIXME: How about resolving things, or is it too risky ? */

  a[0] = 0;
  a[1] = 0;

  i = 0;
  while ((s[i] != '\0') && (s[i] != '/')) {
    i++;
  }

  result = 0;
  if (s[i] == '/') {
    if (i > 15) {
      i = 15;
    }
    memcpy(tmp, s, i);
    tmp[i] = '\0';
    if (inet_aton(tmp, &d) == 0) {
      result++;
    }
    a[1] = 32 - atoi(s + i + 1);
#ifdef DEBUG
    fprintf(stderr, "idsa_ip4addr_scan(): address component is <%s>, number %ld\n", tmp, a[1]);
#endif
    if (a[1] > 32) {
      a[1] = 0;
      result++;
    }
  } else {			/* no /bits component, just plain IP address */
    if (inet_aton(s, &d) == 0) {
      result++;
    }
  }
  a[0] = ntohl(d.s_addr);

#ifdef DEBUG
  fprintf(stderr, "idsa_ip4addr_scan(): 0x%08lx/%ld\n", a[0], a[1]);
#endif

  memcpy(u->u_ptr, a, 2 * sizeof(long int));

  return result;
}

static int idsa_ip4addr_print(IDSA_UNIT * u, char *s, int l, int m)
{
  unsigned long int a[2], z;
  struct in_addr d;
  struct hostent *he;
  struct netent *ne;
  int x;
  char *nh;

  memcpy(a, u->u_ptr, 2 * sizeof(long int));
  nh = NULL;

  if (m >= 100) {
    if (a[1]) {
      z = htonl((0xffffffff << (a[1])) & a[0]);
      ne = getnetbyaddr(z, AF_INET);
#ifdef DEBUG
      fprintf(stderr, "idsa_ip4addr_print(): resolving network %lu\n", z);
#endif
      if (ne != NULL) {
	nh = ne->n_name;
      }
    } else {
      z = htonl(a[0]);
      he = gethostbyaddr((char *) &z, sizeof(z), AF_INET);
#ifdef DEBUG
      fprintf(stderr, "idsa_ip4addr_print(): resolving host %lu\n", z);
#endif
      if (he != NULL) {
	nh = he->h_name;
      }
    }
  }

  if (nh == NULL) {
    d.s_addr = htonl(a[0]);
    if (a[1] > 0) {
      x = snprintf(s, l, "%s/%ld", inet_ntoa(d), 32 - a[1]);
    } else {
      x = snprintf(s, l, "%s", inet_ntoa(d));
    }
    return (x > l) ? (-1) : x;
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_ip4addr_print(): managed to resolve: %s\n", nh);
#endif
    x = strlen(nh);

    if (l < x) {
      memcpy(s, nh, l);		/* feeble best effort */
      return -1;
    }

    memcpy(s, nh, x);
    switch (m - 100) {		/* only useful when resolved */
    case ESCAPE_UNIX:
      return idsa_escape_unix(s, x, l);
    case ESCAPE_XML:
      return idsa_escape_xml(s, x, l);
    default:
      return x;
    }
  }
}

/* port handler (protocol/port) ***************************************** */

static int idsa_ipport_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  unsigned int x[2], y[2];
  int result;

  memcpy(&x, a->u_ptr, 2 * sizeof(int));
  memcpy(&y, b->u_ptr, 2 * sizeof(int));

  if (x[0] < y[0]) {
    result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
  } else if (x[0] > y[0]) {
    result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
  } else {
    if (x[1] < y[1]) {
      result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
    } else if (x[1] > y[1]) {
      result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
    } else {
      result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
    }
  }

  return result;
}

static int idsa_ipport_set(IDSA_UNIT * u, void *p)
{
  memcpy(u->u_ptr, p, 2 * sizeof(int));

  return 0;
}

static int idsa_ipport_get(IDSA_UNIT * u, void *p, int l)
{
  if (l < (2 * sizeof(int))) {
    return -1;
  } else {
    memcpy(p, u->u_ptr, 2 * sizeof(int));
    return (2 * sizeof(int));
  }
}

static int idsa_ipport_scan(IDSA_UNIT * u, char *s)
{
  unsigned int x[2];
  int result = 0;
  char p[32];
  int i;
  struct protoent *pe;
  struct servent *se;

  for (i = 0; (s[i] != '\0') && (s[i] != '/'); i++);

  if ((i < 31) && (s[i] == '/')) {
    memcpy(p, s, i);
    p[i] = '\0';
    i++;

    if (isdigit(p[0])) {
      x[0] = atoi(p);
    } else {
      pe = getprotobyname(p);
      if (pe) {
	x[0] = pe->p_proto;
      } else {
	x[0] = 0;
	result++;
      }
    }

    if (isdigit(s[i])) {
      x[1] = atoi(s + i);
    } else {
      se = getservbyname(s + i, p);
      if (se) {
	x[1] = ntohs(se->s_port);
      } else {
	x[1] = 0;
	result++;
      }
    }

#ifdef DEBUG
    fprintf(stderr, "idsa_ipport_scan(): <%s> maps to %d/%d\n", s, x[0], x[1]);
#endif
    memcpy(u->u_ptr, x, 2 * sizeof(int));

  } else {
    result++;
  }

  return result;
}

#define NBUFFER 32

static int idsa_ipport_print(IDSA_UNIT * u, char *s, int l, int m)
{
  int x[2];
  int y;
  struct protoent *pe;
  struct servent *se;
  char *sp, *pp;
  char sb[NBUFFER], pb[NBUFFER];

  memcpy(&x, u->u_ptr, 2 * sizeof(int));

  if (m < 100) {
    y = snprintf(s, l, "%d/%d", x[0], x[1]);
    return (y > l) ? (-1) : y;
  }

  pe = getprotobynumber(x[0]);
  if (pe) {
    pp = pe->p_name;
  } else {
    snprintf(pb, NBUFFER, "%d", x[0]);
    pp = pb;
  }

  se = getservbyport(htons(x[1]), pp);
  if (se) {
    sp = se->s_name;
  } else {
    snprintf(sb, NBUFFER, "%d", x[1]);
    sp = sb;
  }

  y = snprintf(s, l, "%s/%s", pp, sp);
  if (y > l) {
    return -1;
  }

  switch (m - 100) {
  case ESCAPE_UNIX:
    return idsa_escape_unix(s, y, l);
  case ESCAPE_XML:
    return idsa_escape_xml(s, y, l);
  default:
    return y;
  }

}

/* file handler (absolute path) ***************************************** */

static int idsa_file_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  int result;
  int i, z;

  i = 0;
  z = idsa_type_size(a->u_type);
  while ((i < z) && (a->u_ptr[i] == b->u_ptr[i]) && (a->u_ptr[i] != '\0')) {
    i++;
  }

  if ((a->u_ptr[i] == '\0') || (b->u_ptr[i] == '\0')) {
    if (a->u_ptr[i] == b->u_ptr[i]) {
      result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
    } else {
      if (a->u_ptr[i] == '\0') {
	result = IDSA_COMPARE_LESS;
	if ((i > 0) && (a->u_ptr[i - 1] == '/')) {
	  result |= IDSA_COMPARE_INTERSECT;
	} else {
	  result |= IDSA_COMPARE_DISJOINT;
	}
      } else {
	result = IDSA_COMPARE_MORE;
	if ((i > 0) && (b->u_ptr[i - 1] == '/')) {
	  result |= IDSA_COMPARE_INTERSECT;
	} else {
	  result |= IDSA_COMPARE_DISJOINT;
	}
      }
    }
  } else {
    if (a->u_ptr[i] < b->u_ptr[i]) {
      result = IDSA_COMPARE_LESS | IDSA_COMPARE_DISJOINT;
    } else {
      result = IDSA_COMPARE_MORE | IDSA_COMPARE_DISJOINT;
    }
  }

#ifdef DEBUG
  fprintf(stderr, "compare_file(): comparing of <%s> against <%s>\n", a->u_ptr, b->u_ptr);
#endif

  return result;
}

static int idsa_file_check(IDSA_UNIT * u)
{
  u->u_ptr[idsa_type_size(u->u_type) - 1] = '\0';

  if (u->u_ptr[0] != '/') {
    return 1;
  } else {
    return 0;
  }
}

static int idsa_file_scan(IDSA_UNIT * u, char *s)
{
  int result = 0;
  int m, x, z;
  int dot;

  m = idsa_type_size(u->u_type);

  /* if not absolute path get /dir + / */
  if (s[0] != '/') {
    if (getcwd(u->u_ptr, m - 2)) {
      u->u_ptr[m - 1] = '\0';
      x = strlen(u->u_ptr);
      if ((x == 0) || (u->u_ptr[x - 1] != '/')) {
	u->u_ptr[x++] = '/';
      }
    } else {
      x = 0;
      result = 1;
    }
  } else {
    x = 0;
  }

  /* copy out path, munching /../ and /./ */
  dot = 0;
  z = 0;
  while ((x < m) && (s[z] != '\0')) {
    if (s[z] == '/') {
      if (dot >= 3) {
	dot = 0;
      }
      u->u_ptr[x] = '\0';
      while ((dot > 0) && (x > 0)) {
	if (u->u_ptr[x] == '/') {
	  dot--;
	}
	if (dot) {
	  x--;
	}
      }
      u->u_ptr[x] = '/';
      x++;
      z++;
      dot = 0;
    } else {
      if (s[z] == '.') {
	dot++;
      } else {
	dot = 3;
      }
      u->u_ptr[x] = s[z];
      x++;
      z++;
    }
  }				/* end of loop */

  if (x < m) {
    if (dot >= 3) {
      dot = 0;
    }
    u->u_ptr[x] = '\0';
    while ((dot > 0) && (x > 0)) {
      if (u->u_ptr[x] == '/') {
	dot--;
      }
      if (dot) {
	x--;
      }
    }
    u->u_ptr[x] = '\0';
  } else {
    u->u_ptr[m - 1] = '\0';
    result = 1;
  }

  return result;
}

/* idsa_string_print = idsa_file_print */

static int idsa_file_set(IDSA_UNIT * u, void *p)
{
  return idsa_file_scan(u, p);
}

/* idsa_string_get = idsa_file_get */

/* sockaddr address handler ********************************************* */
/* Slurps in a sockaddr_?? type. Rather messy. FIXME: Not yet complete ** */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#ifdef UNIX_PATH_MAX
#define IDSA_SUN_MAX UNIX_PATH_MAX
#else
#define IDSA_SUN_MAX 108
#endif

struct idsa_sockaddr_map {
  int m_type;
  char *m_string;
};

#undef AF_INET6			/* not yet implemented */

static struct idsa_sockaddr_map idsa_sockaddr_table[] = {
  {AF_LOCAL, "unix"},
  {AF_INET, "ip4"},
#ifdef AF_INET6
  {AF_INET6, "ip6"},
#endif
  {AF_UNSPEC, NULL}		/* aka "unspecified", see code2string */
};

static char *idsa_sockaddr_unknown = "unspecified";

static int idsa_sockaddr_string2code(char *s)
{
  int i;
  for (i = 0; idsa_sockaddr_table[i].m_string != NULL; i++) {
    if (strncmp(idsa_sockaddr_table[i].m_string, s, strlen(idsa_sockaddr_table[i].m_string)) == 0) {
      return idsa_sockaddr_table[i].m_type;
    }
  }

  return AF_UNSPEC;
}

static char *idsa_sockaddr_code2string(int t)
{
  int i;
  for (i = 0; idsa_sockaddr_table[i].m_string != NULL; i++) {
    if (idsa_sockaddr_table[i].m_type == t) {
      return idsa_sockaddr_table[i].m_string;
    }
  }

  return idsa_sockaddr_unknown;
}

static int idsa_sockaddr_size(int type)
{
  int size;

  switch (type) {
  case AF_UNSPEC:
    size = sizeof(unsigned int);
    break;
  case AF_LOCAL:
    size = sizeof(struct sockaddr_un);
    break;
  case AF_INET:
    size = sizeof(struct sockaddr_in);
    break;
#ifdef AF_INET6
  case AF_INET6:
    size = sizeof(struct sockaddr_in6);
    break;
#endif
  default:
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": unknown socket address type %d\n", type);
#endif
    size = 0;
    break;
  }

  if (size > IDSA_M_SADDR) {
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": can not accomodate socket address type %d, size=%d\n", type, size);
#endif
    size = 0;
  }

  return size;
}

static int idsa_sockaddr_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  int result = 0;
  int c;
  struct sockaddr *sx, *sy;
  /* unix socket */
  struct sockaddr_un *sux = NULL, *suy = NULL;
  /* ip4 socket */
  struct sockaddr_in *sni = NULL;
  unsigned long lnx, lny;
  unsigned short snx, sny;

  sx = (struct sockaddr *) (a->u_ptr);
  sy = (struct sockaddr *) (b->u_ptr);

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": comparison between %d and %d\n", sx->sa_family, sy->sa_family);
#endif

  if (sx->sa_family == sy->sa_family) {
    switch (sx->sa_family) {
    case AF_UNSPEC:
      result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
      break;
    case AF_LOCAL:
      sux = (struct sockaddr_un *) sx;
      suy = (struct sockaddr_un *) sy;

      c = strncmp(sux->sun_path, suy->sun_path, IDSA_SUN_MAX);
      if (c == 0) {
	result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
      } else {
	result = ((c > 0) ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS) | IDSA_COMPARE_DISJOINT;
      }
      break;
    case AF_INET:
      sni = (struct sockaddr_in *) sx;
      lnx = ntohl(sni->sin_addr.s_addr);
      snx = ntohs(sni->sin_port);

      sni = (struct sockaddr_in *) sy;
      lny = ntohl(sni->sin_addr.s_addr);
      sny = ntohs(sni->sin_port);

      if ((lnx == lny) || (lnx == 0) || (lny == 0)) {	/* exact match or wildcard */
#ifdef DEBUG
	fprintf(stderr, __FUNCTION__ ": address match\n");
#endif
	if (snx == sny) {	/* same port - exactly the same */
	  result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
	} else {		/* matching ip - approximately equal */
	  result = ((snx > sny) ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS) | IDSA_COMPARE_INTERSECT;
	}
      } else {			/* not matching ip */
#ifdef DEBUG
	fprintf(stderr, __FUNCTION__ ": no address match: 0x%08x 0x%08x\n", lnx, lny);
#endif
	result = ((lnx > lny) ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS) | IDSA_COMPARE_DISJOINT;
      }

      break;
#ifdef AF_INET6
    case AF_INET6:
#ifdef DEBUG
      fprintf(stderr, __FUNCTION__ ": not yet implemented\n");
#endif
      /* FIXME */
      break;
#endif
    default:
#ifdef DEBUG
      fprintf(stderr, __FUNCTION__ ": unknown types should never enter system\n");
#endif
      result = IDSA_COMPARE_MORE | IDSA_COMPARE_INTERSECT;
      break;
    }
  } else {
    result = IDSA_COMPARE_DISJOINT | (sx->sa_family > sy->sa_family ? IDSA_COMPARE_MORE : IDSA_COMPARE_LESS);
  }

  return result;
}

static int idsa_sockaddr_check(IDSA_UNIT * u)
{
  struct sockaddr *sx;
  int size;

  sx = (struct sockaddr *) (u->u_ptr);

  size = idsa_sockaddr_size(sx->sa_family);

  if (size == 0) {
    sx->sa_family = AF_UNSPEC;
  }

  return 0;			/* can't do anything else, as otherwise upgrades on other side cause abort */
}

static int idsa_sockaddr_set(IDSA_UNIT * u, void *p)
{
  struct sockaddr *sx;
  int size;

  sx = (struct sockaddr *) p;
  size = idsa_sockaddr_size(sx->sa_family);

  if (size > 0) {
    memcpy(u->u_ptr, p, size);
    return 0;
  } else {
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": unknown type %d, demoting to unspecified\n", sx->sa_family);
#endif
    sx = (struct sockaddr *) u->u_ptr;
    sx->sa_family = AF_UNSPEC;
    return 1;
  }

  return 1;
}

static int idsa_sockaddr_get(IDSA_UNIT * u, void *p, int l)
{
  struct sockaddr *sx;
  int size;

  sx = (struct sockaddr *) (u->u_ptr);
  size = idsa_sockaddr_size(sx->sa_family);

  if (size > 0) {
    if (l < size) {
      return -1;
    }
    memcpy(p, u->u_ptr, size);
    return size;
  }
#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": impossible error, unknown socket type\n");
#endif

  return -1;
}

#define IDSA_TMP_SCAN 64

static int idsa_sockaddr_scan(IDSA_UNIT * u, char *s)
{
  struct sockaddr *sx;
  struct sockaddr_un *sux;
  struct sockaddr_in *six;
  int size;
  int result;
  char *address, *port;
  char tmp[IDSA_TMP_SCAN];

  sx = (struct sockaddr *) (u->u_ptr);
  sx->sa_family = idsa_sockaddr_string2code(s);

  size = idsa_sockaddr_size(sx->sa_family);
  result = 0;

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": got size=%d for %s\n", size, s);
#endif

  switch (sx->sa_family) {
  case AF_UNSPEC:
    /* do nothing */
    break;
  case AF_LOCAL:
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": copying unix=%s\n", s);
#endif
    sux = (struct sockaddr_un *) sx;
    address = strchr(s, ':');
    if (address) {
      strncpy(sux->sun_path, address + 1, IDSA_SUN_MAX - 1);
      sux->sun_path[IDSA_SUN_MAX - 1] = '\0';
    } else {
      sux->sun_path[0] = '\0';
      result++;
    }
    break;
  case AF_INET:
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": copying inet=%s\n", s);
#endif
    six = (struct sockaddr_in *) sx;

    /* copy needed since inet_addr wants zero termination, not continued text */
    strncpy(tmp, s, IDSA_TMP_SCAN - 1);
    tmp[IDSA_TMP_SCAN - 1] = '\0';

    address = strchr(tmp, '/');
    if (address) {
      address++;
      port = strchr(address, ':');
      if (port == address) {
	address = NULL;
      }
      if (port) {
	port[0] = '\0';
	port++;
      }
    } else {
      port = NULL;
    }

#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": address=%s, port=%s\n", address, port);
#endif

    if (address) {
      six->sin_addr.s_addr = inet_addr(address);
    } else {
      six->sin_addr.s_addr = htonl(0);
    }
    if (port) {
      six->sin_port = htons(atoi(port));
    } else {
      six->sin_port = htons(0);
    }

#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": recovered 0x%08x:%04x\n", six->sin_addr.s_addr, six->sin_port);
#endif

    break;
#ifdef AF_INET6
  case AF_INET6:
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": unimplemented\n");
#endif
    /* FIXME */
    break;
#endif
  }

  return result;
}

static int idsa_sockaddr_print(IDSA_UNIT * u, char *s, int l, int m)
{
  struct sockaddr *sx;
  struct sockaddr_un *sux;
  struct sockaddr_in *six;
  char *n;
  int x, y;

  sx = (struct sockaddr *) (u->u_ptr);
  n = idsa_sockaddr_code2string(sx->sa_family);

  if (n) {
    y = strlen(n);
    if (y > l) {
      strncpy(s, n, l);
      return -1;
    } else {
      strncpy(s, n, y);
      x = y;
    }
  } else {
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": code2string should always return something\n");
#endif
    return -1;
  }

  /* FIXME: could resolve names in here */

  switch (sx->sa_family) {
  case AF_UNSPEC:
    return x;
    break;
  case AF_LOCAL:
    if (l < x + 1) {
      return -1;
    }
    s[x++] = ':';

    sux = (struct sockaddr_un *) sx;
    y = 0;
    while ((x < l) && (y < IDSA_SUN_MAX) && (sux->sun_path[y] != '\0')) {
      s[x++] = sux->sun_path[y++];
    }

    if ((y < IDSA_SUN_MAX) && (sux->sun_path[y] != '\0')) {
      return -1;
    }

    return x;
    break;
  case AF_INET:
    six = (struct sockaddr_in *) sx;

#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": 0x%08x:%04x : %s\n", six->sin_addr.s_addr, six->sin_port, inet_ntoa(six->sin_addr));
#endif

    y = snprintf(s + x, l - x, "/%s:%hu", inet_ntoa(six->sin_addr), ntohs(six->sin_port));
    if (y < 0) {
      return -1;
    }
    if (x + y > l) {
      return -1;
    }
    return x + y;
    break;
#ifdef AF_INET6
  case AF_INET6:
#ifdef DEBUG
    fprintf(stderr, __FUNCTION__ ": unimplemented\n");
#endif
    /* FIXME */
    break;
#endif
  }

#ifdef DEBUG
  fprintf(stderr, __FUNCTION__ ": should not happen\n");
#endif
  return -1;
}

/****************************************************************************/

struct idsa_type_details {
  unsigned int l_type;
  unsigned int l_size;
  unsigned int l_cform;
  char l_name[IDSA_M_NAME];
  IDSA_FUNCTION_COMPARE l_compare;
  IDSA_FUNCTION_CHECK l_check;
  IDSA_FUNCTION_SET l_set;
  IDSA_FUNCTION_GET l_get;
  IDSA_FUNCTION_SCAN l_scan;
  IDSA_FUNCTION_PRINT l_print;
};

static IDSA_TYPE_DETAILS idsa_type_table[IDSA_M_TYPES] = {
  [0] = {IDSA_T_NULL,
	 0,
	 0,
	 "",
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL,
	 NULL},

  [IDSA_T_STRING] = {IDSA_T_STRING,
		     IDSA_M_STRING,
		     0,
		     "string",
		     &idsa_string_compare,
		     &idsa_string_check,
		     &idsa_string_set,
		     &idsa_string_get,
		     &idsa_string_scan,
		     &idsa_string_print},

  [IDSA_T_INT] = {IDSA_T_INT,
		  sizeof(int),
		  0,
		  "integer",
		  &idsa_int_compare,
		  NULL,
		  &idsa_int_set,
		  &idsa_int_get,
		  &idsa_int_scan,
		  &idsa_int_print},

  [IDSA_T_UID] = {IDSA_T_UID,
		  sizeof(uid_t),
		  0,
		  "uid",
		  &idsa_uid_compare,
		  NULL,
		  &idsa_uid_set,
		  &idsa_uid_get,
		  &idsa_uid_scan,
		  &idsa_uid_print}
  ,

  [IDSA_T_GID] = {IDSA_T_GID,
		  sizeof(gid_t),
		  0,
		  "gid",
		  &idsa_gid_compare,
		  NULL,
		  &idsa_gid_set,
		  &idsa_gid_get,
		  &idsa_gid_scan,
		  &idsa_gid_print}
  ,

  [IDSA_T_PID] = {IDSA_T_PID,
		  sizeof(pid_t),
		  0,
		  "pid",
		  &idsa_pid_compare,
		  NULL,
		  &idsa_pid_set,
		  &idsa_pid_get,
		  &idsa_pid_scan,
		  &idsa_pid_print}
  ,

  [IDSA_T_TIME] = {IDSA_T_TIME,
		   sizeof(time_t),
		   0,
		   "time",
		   &idsa_time_compare,
		   NULL,
		   &idsa_time_set,
		   &idsa_time_get,
		   &idsa_time_scan,	/* needs improvement */
		   &idsa_time_print}
  ,

  [IDSA_T_FLAG] = {IDSA_T_FLAG,
		   sizeof(int),
		   0,
		   "flag",
		   &idsa_flag_compare,
		   NULL,
		   &idsa_flag_set,
		   &idsa_flag_get,
		   &idsa_flag_scan,
		   &idsa_flag_print},

  [IDSA_T_RISK] = {IDSA_T_RISK,
		   sizeof(int),
		   0,
		   "risk",
		   &idsa_risk_compare,
		   NULL,
		   &idsa_risk_set,
		   &idsa_risk_get,
		   &idsa_risk_scan,
		   &idsa_risk_print},

  [IDSA_T_ERRNO] = {IDSA_T_ERRNO,
		    sizeof(int),
		    0,
		    "errno",
		    &idsa_int_compare,
		    NULL,
		    &idsa_int_set,
		    &idsa_int_get,
		    &idsa_int_scan,
		    &idsa_errno_print},

  [IDSA_T_HOST] = {IDSA_T_HOST,
		   IDSA_M_STRING,
		   0,
		   "host",
		   &idsa_host_compare,
		   &idsa_host_check,
		   &idsa_host_set,
		   &idsa_host_get,
		   &idsa_host_scan,
		   &idsa_host_print},

  [IDSA_T_IP4ADDR] = {IDSA_T_IP4ADDR,
		      2 * sizeof(unsigned long),
		      0,
		      "addr",
		      &idsa_ip4addr_compare,
		      &idsa_ip4addr_check,
		      &idsa_ip4addr_set,
		      &idsa_ip4addr_get,
		      &idsa_ip4addr_scan,
		      &idsa_ip4addr_print},

  [IDSA_T_IPPORT] = {IDSA_T_IPPORT,
		     2 * sizeof(unsigned int),
		     0,
		     "port",
		     &idsa_ipport_compare,
		     NULL,
		     &idsa_ipport_set,
		     &idsa_ipport_get,
		     &idsa_ipport_scan,
		     &idsa_ipport_print},

  [IDSA_T_FILE] = {IDSA_T_FILE,
		   IDSA_M_FILE,
		   0,
		   "file",
		   &idsa_file_compare,
		   &idsa_file_check,
		   &idsa_file_set,
		   &idsa_string_get,
		   &idsa_file_scan,
		   &idsa_string_print},
  [IDSA_T_SADDR] = {IDSA_T_SADDR,
		    IDSA_M_SADDR,
		    0,
		    "saddr",
		    &idsa_sockaddr_compare,
		    &idsa_sockaddr_check,
		    &idsa_sockaddr_set,
		    &idsa_sockaddr_get,
		    &idsa_sockaddr_scan,
		    &idsa_sockaddr_print}
};

int idsa_unit_compare(IDSA_UNIT * a, IDSA_UNIT * b)
{
  IDSA_TYPE_DETAILS *l;

  if (a->u_type != b->u_type) {
    if (a->u_type < b->u_type) {
      return IDSA_COMPARE_LESS;
    } else {
      return IDSA_COMPARE_MORE;
    }
  }

  l = idsa_type_lookup(a->u_type);
  if (l) {
    return (*(l->l_compare)) (a, b);
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_unit_compare(): assertion failure: no compare function available\n");
    abort();
#endif
    return IDSA_COMPARE_LESS;
  }
}

int idsa_unit_check(IDSA_UNIT * u)
{
  IDSA_TYPE_DETAILS *t;
  int i;

  /* probably name check not needed anymore */
  u->u_name[IDSA_M_NAME - 1] = '\0';
  for (i = 0; u->u_name[i] != '\0'; i++) {
    if (!isalnum(u->u_name[i])) {
      switch (u->u_name[i]) {
      case '.':
      case '_':
      case '-':
	break;
      default:
	u->u_name[i] = '_';
	break;
      }
    }
  }

  t = idsa_type_lookup(u->u_type);
  if (t) {
    if (t->l_check) {
      return (*(t->l_check)) (u);
    } else {
      return 0;
    }
  } else {
    return 1;
  }
}

int idsa_unit_get(IDSA_UNIT * u, void *p, int l)
{
  IDSA_TYPE_DETAILS *t;

#ifdef DEBUG
  fprintf(stderr, "idsa_unit_get(): looking up type <0x%04x>\n", u->u_type);
#endif

  t = idsa_type_lookup(u->u_type);
  if (t) {
    return (*(t->l_get)) (u, p, l);
  } else {
    return 1;
  }
}

int idsa_unit_set(IDSA_UNIT * u, void *p)
{
  IDSA_TYPE_DETAILS *t;

#ifdef DEBUG
  fprintf(stderr, "idsa_unit_set(): setting type <0x%04x> (address %p)\n", u->u_type, p);
#endif

  t = idsa_type_lookup(u->u_type);
  if (t) {
    return (*(t->l_set)) (u, p);
  } else {
    return 1;
  }
}

int idsa_unit_scan(IDSA_UNIT * u, char *s)
{
  IDSA_TYPE_DETAILS *t;

  t = idsa_type_lookup(u->u_type);
  if (t) {
    return (*(t->l_scan)) (u, s);
  } else {
    return 1;
  }
}

int idsa_unit_print(IDSA_UNIT * u, char *s, int l, int m)
{
  IDSA_TYPE_DETAILS *t;

  t = idsa_type_lookup(u->u_type);
  if (t) {
    return (*(t->l_print)) (u, s, l, m);
  } else {
    return -1;
  }
}

/****************************************************************************/

IDSA_TYPE_DETAILS *idsa_type_lookup(unsigned int t)
{
  IDSA_TYPE_DETAILS *result;
  unsigned int i;

  i = t;
  if (i > 0 && i < IDSA_M_TYPES) {
    result = &(idsa_type_table[i]);
    if (result->l_type != t) {
#ifdef DEBUG
      fprintf(stderr, "idsa_type_lookup(): sanity failure, type table corruption - have <0x%04x>, want <0x%04x>\n", result->l_type, t);
#endif
      result = NULL;
    }
  } else {
#ifdef DEBUG
    fprintf(stderr, "idsa_type_lookup(): unknown type 0x%04x\n", t);
#endif
    result = NULL;

  }

  return result;
}

char *idsa_type_name(unsigned int t)
{
  IDSA_TYPE_DETAILS *l;

  l = idsa_type_lookup(t);
  if (l) {
    return l->l_name;
  } else {
    return NULL;
  }
}

unsigned int idsa_type_code(char *n)
{
  int i;

  for (i = 1; i < IDSA_M_TYPES; i++) {
#ifdef DEBUG
    fprintf(stderr, "idsa_type_code(): looking at <%s:0x%04x>\n", idsa_type_table[i].l_name, idsa_type_table[i].l_type);
#endif
    if (strcmp(n, idsa_type_table[i].l_name) == 0) {
      return idsa_type_table[i].l_type;
    }
  }
  return IDSA_T_NULL;
}

int idsa_type_size(unsigned int t)
{
  IDSA_TYPE_DETAILS *l;

  l = idsa_type_lookup(t);
  if (l) {
    return l->l_size;
  } else {
    return 0;
  }
}
