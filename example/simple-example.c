
/****************************************************************************/
/*                                                                          */
/* simple example: This application registers itself as service "example",  */
/*                 and reports two events in the scheme "mo"                */
/*                                                                          */
/****************************************************************************/

#include <stdlib.h>
#include <stdio.h>

#include <idsa.h>

int main(int argc, char **argv)
{
  IDSA_CONNECTION *c;
  int result;

  /* connect to idsad as example service, no credential,
   * allow environment variable overrides 
   */
  c = idsa_open("example", NULL, IDSA_F_ENV);
  if (c == NULL) {
    fprintf(stderr, "%s: unable to initialize\n", argv[0]);
    exit(1);
  }

  /* report an event named "eenie" in namepace "mo" with unknown risks */
  result = idsa_set(c, "eenie", "mo", 1, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, NULL);

  /* check if event is allowed or denied */
  if (result == IDSA_L_ALLOW) {
    printf("%s: allow eenie\n", argv[0]);
  } else {
    printf("%s: deny eenie\n", argv[0]);
  }

  /* report an event named "meenie" in namepace "mo" with 
   * a high risk to integrity, and an optional field "catcha:string tiger"
   */
  if (idsa_set(c, "meenie", "mo", 1, IDSA_R_UNKNOWN, IDSA_R_UNKNOWN, IDSA_R_TOTAL, "catcha", IDSA_T_STRING, "tiger", NULL) == IDSA_L_ALLOW) {
    printf("%s: allow meenie\n", argv[0]);
  } else {
    printf("%s: deny meenie\n", argv[0]);
  }

  /* close connection */
  idsa_close(c);

  fflush(stdout);

  return 0;
}
