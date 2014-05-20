#ifndef _IDSA_UDOMAIN_H_
#define _IDSA_UDOMAIN_H_

#include <sys/types.h>

int udomainlisten(char *s, int b, int z);
int udomainconnect(char *s);
pid_t udomainowner(char *s);

#endif

