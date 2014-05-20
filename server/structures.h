#ifndef _IDSAD_STRUCTURES_H_
#define _IDSAD_STRUCTURES_H_

#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/types.h>

#include <idsa_internal.h>

struct job{
  int j_fd;

  pid_t j_pid;
  gid_t j_gid;
  uid_t j_uid;

  int j_state; /* should only be touched in job.c */

  int j_rl; /* read buffer length */
  char j_rbuf[IDSA_M_MESSAGE];

  int j_wl; /* write buffer length */
  char j_wbuf[IDSA_M_MESSAGE];

  /* if interleaved would need separate local, request and reply */
};
typedef struct job JOB;

struct state_set{
  IDSA_RULE_CHAIN *s_chain; /* the rule system */
  IDSA_RULE_LOCAL *s_local; /* local rule part */

  IDSA_EVENT *s_request;    /* event received from client */
  IDSA_EVENT *s_reply;      /* event sent to client */

  IDSA_EVENT *s_libidsa;    /* messages generated inside libidsa */
  IDSA_EVENT *s_idsad;      /* messages generated in idsad */
  IDSA_EVENT *s_template;   /* template for internal messages */

  JOB *s_jobs;              /* table of client connections */
  int s_jobsize;            /* current size of table */
  int s_jobmax;             /* maximum size of table */

  int s_jobcount;           /* number of entries used */
  int s_jobquota;           /* number of entries per user */

  char *s_hostname;         /* cached hostname */
  gid_t s_gid;              /* cached gid */
  time_t s_time;            /* cached time */
};
typedef struct state_set STATE_SET;

#endif
