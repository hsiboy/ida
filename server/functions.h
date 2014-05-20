#ifndef _IDSAD_FUNCTIONS_H_
#define _IDSAD_FUNCTIONS_H_

#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>

#include <idsa_internal.h>

#include "structures.h"

/****************************************************************************/

#define JOB_STATEFIN         0x00  /* end, close connection */
#define JOB_STATEWAIT        0x01  /* wait for event from client */
#define JOB_STATEWRITE       0x02  /* send result to client */

#define job_isend(j)   ((j->j_state!=JOB_STATEWRITE)&&(j->j_state!=JOB_STATEWAIT))
#define job_iswrite(j) ((j->j_state==JOB_STATEWRITE)||(j->j_wl>0))
#define job_iswork(j)  ((j->j_state==JOB_STATEWAIT)&&(j->j_rl>0))

int job_accept(JOB *j, int fd);
void job_copy(JOB *t, JOB *s);
void job_drop(int fd);
int job_end(JOB *j);

int job_write(JOB *j);
int job_read(JOB *j);

int job_do(JOB *j, STATE_SET *s);

/****************************************************************************/

#define IDSA_IO_OK   0
#define IDSA_IO_WAIT 1
#define IDSA_IO_FAIL 2

int io_readmessage(STATE_SET *s, JOB *j, IDSA_EVENT *e);
int io_writereply(STATE_SET *s, JOB *j, IDSA_EVENT *e);

int io_drain(JOB *j);

/****************************************************************************/

STATE_SET *set_new(int max, int start, int quota);
int set_parse(STATE_SET * s, char * file);
void set_free(STATE_SET *s);

/****************************************************************************/

int message_stderr(STATE_SET *s);

int message_chain(STATE_SET *s);

int message_start(STATE_SET *s, char *v);
int message_stop(STATE_SET *s, char *v);

int message_connect(STATE_SET *s, pid_t p, uid_t u, gid_t g);
int message_disconnect(STATE_SET *s, pid_t p, uid_t u, gid_t g);

int message_error_system(STATE_SET * s, int err, char *str, ...);
int message_error_internal(STATE_SET * s, char *str, ...);

#endif
