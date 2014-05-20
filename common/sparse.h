#ifndef PARSE_H_
#define PARSE_H_

int parse_event(IDSA_EVENT * evt, char *buf);
int parse_extra(IDSA_EVENT * evt, char *service, char *message);

#endif
