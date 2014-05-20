#include <stdlib.h>
#include <stdio.h>

#include <idsa_internal.h>

#define IDSA_SYSLOG_SEVERITY_MAX     8	/* number of severities */
#define IDSA_SYSLOG_FACILITY_KNOWN  12	/* number of RESERVED facilities */
#define IDSA_SYSLOG_FACILITY_LOCAL  16	/* offset where LOCAL facilities start */

#define IDSA_SYSLOG_FACILITY "facility"
#define IDSA_SYSLOG_SEVERITY "severity"
#define IDSA_SYSLOG_RESERVED "reserved"
#define IDSA_SYSLOG_LOCAL       "local"

#define IDSA_SYSLOG_MESSAGE   "message"
#define IDSA_SYSLOG_SCHEME     "syslog"

struct idsa_syslog_severity {	/* lookup table for severities */
  char *t_name;
  double t_confidence[IDSA_M_RISKS];
  double t_severity[IDSA_M_RISKS];
};

struct idsa_syslog_facility {	/* lookup table for facilities */
  char *t_name;
};

static struct idsa_syslog_severity
 idsa_severity_table[IDSA_SYSLOG_SEVERITY_MAX] = {
  [0] = {"emerg",
	 {0.857, 0.0, 0.857},
	 {1.000, 0.0, 1.000}},
  [1] = {"alert",
	 {0.857, 0.0, 0.857},
	 {0.857, 0.0, 0.857}},
  [2] = {"crit",
	 {0.857, 0.0, 0.857},
	 {0.714, 0.0, 0.714}},
  [3] = {"err",
	 {0.857, 0.0, 0.857},
	 {0.571, 0.0, 0.571}},
  [4] = {"warning",
	 {0.857, 0.0, 0.857},
	 {0.429, 0.0, 0.429}},
  [5] = {"notice",
	 {0.857, 0.0, 0.857},
	 {0.286, 0.0, 0.286}},
  [6] = {"info",
	 {0.857, 0.0, 0.857},
	 {0.143, 0.0, 0.143}},
  [7] = {"debug",
	 {0.0, 0.0, 0.0},
	 {0.0, 0.0, 0.0}}
};

static struct idsa_syslog_facility
 idsa_facility_table[IDSA_SYSLOG_FACILITY_KNOWN] = {
  [0] = {"kern"},
  [1] = {"user"},
  [2] = {"mail"},
  [3] = {"daemon"},
  [4] = {"auth"},
  [5] = {"syslog"},
  [6] = {"lpr"},
  [7] = {"news"},
  [8] = {"uucp"},
  [9] = {"cron"},
  [10] = {"authpriv"},
  [11] = {"ftp"}
};

#define FBUFFER 32
#define PBUFFER 32

static unsigned int idsa_syspri2r(int pri, int i)
{
  struct idsa_syslog_severity *index;

  index = &(idsa_severity_table[pri & 0x07]);

  return idsa_risk_make(index->t_severity[i], index->t_confidence[i]);
}

unsigned int idsa_syspri2a(int pri)
{
  return idsa_syspri2r(pri, 0);
}

unsigned int idsa_syspri2c(int pri)
{
  return idsa_syspri2r(pri, 1);
}

unsigned int idsa_syspri2i(int pri)
{
  return idsa_syspri2r(pri, 2);
}

char *idsa_syspri2severity(int pri)
{
  return idsa_severity_table[pri & 0x07].t_name;
}

void idsa_syslog(IDSA_CONNECTION * c, int pri, char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  idsa_vsyslog(c, pri, fmt, args);
  va_end(args);
}

#define BUFFER_SL 1024

void idsa_vsyslog(IDSA_CONNECTION * c, int pri, char *fmt, va_list args)
{
  char message[BUFFER_SL];
  IDSA_EVENT *e;

  if (c) {
    e = idsa_event(c);

    if (e) {
      /* WARNING: my version of glibc understands %m */
      vsnprintf(message, BUFFER_SL - 1, fmt, args);

      message[BUFFER_SL - 1] = '\0';

      idsa_event_syslog(e, pri, message);

      idsa_scheme(e, IDSA_SYSLOG_SCHEME);

      idsa_log(c, e);
    }
  }
}

int idsa_event_syslog(IDSA_EVENT * e, int pri, char *msg)
{
  int result = 0;

  char *facility = NULL;
  char *severity = NULL;

  char fbuffer[FBUFFER];
  char pbuffer[PBUFFER];

  unsigned int ar, cr, ir;

  unsigned fnum;
  fnum = (pri >> 3);
  if (fnum < IDSA_SYSLOG_FACILITY_KNOWN) {
    facility = idsa_facility_table[fnum].t_name;
  } else {
    if (fnum < IDSA_SYSLOG_FACILITY_LOCAL) {
      snprintf(fbuffer, FBUFFER - 1, "%s%d", IDSA_SYSLOG_RESERVED, fnum);
    } else {
      snprintf(fbuffer, FBUFFER - 1, "%s%d", IDSA_SYSLOG_LOCAL, fnum - IDSA_SYSLOG_FACILITY_LOCAL);
    }
    fbuffer[FBUFFER - 1] = '\0';
    facility = fbuffer;
  }
  result += idsa_add_string(e, IDSA_SYSLOG_FACILITY, facility);

  severity = idsa_syspri2severity(pri);
  result += idsa_add_string(e, IDSA_SYSLOG_SEVERITY, severity);

  ar = idsa_syspri2a(pri);
  cr = idsa_syspri2c(pri);
  ir = idsa_syspri2i(pri);
  result += idsa_risks(e, 0, ar, cr, ir);

  snprintf(pbuffer, PBUFFER - 1, "%s.%s", facility, severity);
  pbuffer[PBUFFER - 1] = '\0';
  result += idsa_name(e, pbuffer);

  result += idsa_add_string(e, IDSA_SYSLOG_MESSAGE, msg);

  return result;
}
