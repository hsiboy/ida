
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/utsname.h>

#include "idsad.h"
#include "structures.h"
#include "functions.h"

/****************************************************************************/

STATE_SET *set_new(int max, int start, int quota)
{
  STATE_SET *s;
  struct utsname ut;

  s = malloc(sizeof(STATE_SET));
  if (s == NULL) {
    return NULL;
  }

  /* filled in later */
  s->s_chain = NULL;
  s->s_local = NULL;
  s->s_gid = 0;

  /* keep set_free from freeing nonexistant stuff */
  s->s_hostname = NULL;
  s->s_jobs = NULL;
  s->s_request = NULL;
  s->s_reply = NULL;
  s->s_template = NULL;
  s->s_libidsa = NULL;
  s->s_idsad = NULL;

  s->s_time = time(NULL);
  s->s_hostname = strdup(uname(&ut) ? "localhost" : ut.nodename);
  if (s->s_hostname == NULL) {
    set_free(s);
    return NULL;
  }

  s->s_jobmax = max;		/* never have more than this number of clients */
  s->s_jobsize = start;		/* start with a small table, grow if needed */
  s->s_jobquota = quota;
  s->s_jobcount = 0;
  s->s_jobs = malloc(sizeof(JOB) * s->s_jobsize);
  if (s->s_jobs == NULL) {
    set_free(s);
    return NULL;
  }

  s->s_request = idsa_event_new(0);
  s->s_reply = idsa_event_new(0);
  s->s_template = idsa_event_new(0);
  s->s_libidsa = idsa_event_new(0);
  s->s_idsad = idsa_event_new(0);
  if (!(s->s_request && s->s_reply && s->s_libidsa && s->s_idsad && s->s_template)) {
    set_free(s);
    return NULL;
  }

  idsa_request_init(s->s_template, "idsad", "idsa", NULL);
  idsa_event_copy(s->s_libidsa, s->s_template);
  idsa_event_copy(s->s_idsad, s->s_template);

  return s;
}

static char *idsad_chain_name = IDSAD_CHAINNAME;

int set_parse(STATE_SET * s, char *file)
{
  s->s_chain = idsa_parse_file(s->s_libidsa, file, 0);
  if (s->s_chain == NULL) {
    return 1;
  }

  idsa_chain_setname(s->s_chain, idsad_chain_name);

  s->s_local = idsa_local_new(s->s_chain);

  return idsa_chain_failure(s->s_chain);
}

void set_free(STATE_SET * s)
{
  JOB *j;
  int i;

  if (s->s_local) {
    /* idsa_local_quit(s->s_chain, s->s_local); */
    idsa_local_free(s->s_chain, s->s_local);
    s->s_local = NULL;
  }

  if (s->s_chain) {
    idsa_chain_stop(s->s_chain);
    s->s_chain = NULL;
  }

  /* delete hostname */
  if (s->s_hostname) {
    free(s->s_hostname);
    s->s_hostname = NULL;
  }

  /* close jobs */
  if (s->s_jobs) {
    for (i = 0; i < s->s_jobcount; i++) {
      j = &(s->s_jobs[i]);
      job_end(j);
    }
    free(s->s_jobs);
    s->s_jobs = NULL;
    s->s_jobsize = 0;
    s->s_jobcount = 0;
  }

  if (s->s_request) {
    idsa_event_free(s->s_request);
    s->s_request = NULL;
  }
  if (s->s_reply) {
    idsa_event_free(s->s_reply);
    s->s_reply = NULL;
  }

  if (s->s_idsad) {
    idsa_event_free(s->s_idsad);
    s->s_idsad = NULL;
  }
  if (s->s_libidsa) {
    idsa_event_free(s->s_libidsa);
    s->s_libidsa = NULL;
  }

  if (s->s_template) {
    idsa_event_free(s->s_template);
    s->s_template = NULL;
  }

  free(s);
}
