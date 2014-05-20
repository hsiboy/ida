/****************************************************************************/
/*                                                                          */
/*  This used to be a fancy protocol, but got lobotomized and should get    */
/*  pruned down to a single request / reply pair. The protocol itself could */
/*  also do with some improving - possible improvements:                    */
/*                                                                          */
/*    variable sized units (ick, need to hack event.c and unit.c)           */
/*    network ordering                                                      */
/*    plain text                                                            */
/*    ASN.1: if the ISO decides to make their specs opensource              */
/*    some lightweight markup: I am reluctant to use XML because of size    */
/*                             and security concerns (eg: aliasing and      */
/*                             encodings)                                   */
/*                                                                          */
/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <idsa_internal.h>

/****************************************************************************/
/* Does       : drop event into buffer                                      */
/* Returns    : amount copied on success, zero on failure                   */

int idsa_event_tobuffer(IDSA_EVENT * e, char *s, int l)
{
  if (l >= e->e_size) {
    memcpy(s, e, e->e_size);
    return e->e_size;
  } else {
    return -1;
  }
}

/****************************************************************************/
/* Does       : copy event from buffer                                      */
/* Returns    : amount copied on success, -1 on failure                     */

int idsa_event_frombuffer(IDSA_EVENT * e, char *s, int l)
{
  if (l > sizeof(unsigned int) * 2) {
    /* 2*int <= l <= IDSA_M_MESSAGE: reasonable buffer */
    if (l > IDSA_M_MESSAGE) {
      l = IDSA_M_MESSAGE;
    }
    memcpy(e, s, (sizeof(unsigned int) * 2));

    /* IDSA_S_OFFSET <= size <= IDSA_M_MESSAGE: ok request length */
    if ((e->e_size >= IDSA_S_OFFSET) && (e->e_size <= IDSA_M_MESSAGE)) {
      if (e->e_size <= l) {	/* buffer long enough */
	memcpy(e, s, e->e_size);
	return e->e_size;
      } else {			/* buffer too short */
	return -1;
      }
    } else {			/* buggered event, block indefinitely */
      return -1;
    }
  } else {			/* buffer way too short */
    return -1;
  }
}
