#ifndef _IDSA_IDSAD_H_
#define _IDSA_IDSAD_H_

/* location of configuration file */
#ifndef IDSAD_CONFIG 
#define IDSAD_CONFIG "/etc/idsad.conf"
#endif

#ifndef IDSAD_CHAINNAME
#define IDSAD_CHAINNAME "server"
#endif

/* number of connections to have pending on socket */
#ifndef IDSAD_BACKLOG 
#define IDSAD_BACKLOG 2
#endif

/* starting size of job table */
#ifndef IDSAD_JOBSTART
#define IDSAD_JOBSTART 64
#endif

/* maximum number of jobs per nonroot uid */
#ifndef IDSAD_JOBQUOTA
#define IDSAD_JOBQUOTA 32
#endif

#endif
