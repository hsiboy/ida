/* This execv[e] wrapper is a derrivative of snoopy 1.2 by Marius Aamodt
 * Eriksen and Mike Baker. Their copyright notice is reproduced below.
 */

/* snoopy.c -- execve() logging wrapper 
 * Copyright (c) 2000 marius@linux.com,mbm@linux.com
 * 
 * $Id: snoopy.c,v 1.3 2001/01/14 03:33:58 writer Exp writer $
 *
 * Part hacked on flight KL 0617, 30,000 ft or so over the Atlantic :) 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <idsa.h>

#if defined(RTLD_NEXT)
#define REAL_LIBC RTLD_NEXT
#else
#define REAL_LIBC ((void *) -1L)
#endif

#define FN(ptr,type,name,args)  ptr = (type (*)args)dlsym (REAL_LIBC, name)
#define ARGB 16

int log(char *filename, char **argv)
{

  IDSA_CONNECTION *c;
  IDSA_EVENT *e;

  char argb[ARGB];
  int i;

  c = idsa_open("snoopy", NULL, IDSA_F_FAILOPEN);
  if (c == NULL) {
    return 1;
  }
  e = idsa_event(c);
  if (e == NULL) {
    idsa_close(c);
    return 1;
  }
  idsa_name(e, "exec");
  idsa_scheme(e, "syscall");
  idsa_risks(e, 1, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN);
  idsa_add_scan(e, "filename", IDSA_T_FILE, filename);

  for (i = 0; argv[i] != NULL; i++) {
    snprintf(argb, ARGB, "arg%d", i);
    argb[ARGB - 1] = '\0';
    idsa_add_string(e, argb, argv[i]);
  }

  /* idsa_log deallocates e automatically */
  if (idsa_log(c, e) == IDSA_L_ALLOW) {
    idsa_close(c);
    return 1;
  } else {
    idsa_close(c);
    return 0;
  }
}

int execve(char *filename, char **argv, char **envp)
{
  static int (*func) (const char *, char **, char **);

  FN(func, int, "execve", (const char *, char **, char **));

  if (log(filename, argv)) {
    return (*func) (filename, argv, envp);
  } else {
    errno = EPERM;
    return -1;
  }
}

int execv(char *filename, char **argv)
{
  static int (*func) (const char *, char **);

  FN(func, int, "execv", (const char *, char **));

  if (log(filename, argv)) {
    return (*func) (filename, argv);
  } else {
    errno = EPERM;
    return -1;
  }
}
