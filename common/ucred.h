#ifndef _IDSA_UCRED_H_
#define _IDSA_UCRED_H_

#include <sys/socket.h>

#ifdef IDSA_HAVE_UCRED /* peachy, SO_PEERCRED and struct ucred exist */

#define IDSA_UCRED struct ucred

#else /* yikes, don't exist */

struct idsa_ucred {
  unsigned int pid;
  unsigned int uid;
  unsigned int gid;
};
#define IDSA_UCRED struct idsa_ucred

#ifndef SO_PEERCRED
#warning SO_PEERCRED unavailable
#endif

#endif

#endif
