#ifndef _IDSA_MISC_H_
#define _IDSA_MISC_H_

void drop_root(char *name, char *id, char *rootdir);
void drop_fork(char *name);
void fork_parent(char *name);

int strexec(char *s);

int test_port(unsigned short p);

#endif
