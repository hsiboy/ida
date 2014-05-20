
#define PAM_SM_AUTH


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include <idsa_internal.h>
#include <idsa_schemes.h>

#include <security/pam_modules.h>

#define IDSA_PAM_SCHEME  "pam"
#define IDSA_PAM_SERVICE "pam"	/* only used if nothing else found */

/* authentication */

struct idsa_pam_item {
  char *r_name;
  unsigned int r_risk;
};

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  IDSA_CONNECTION *cn;
  IDSA_EVENT *ev;
  int i, j, len, found;
  struct passwd *pwd;

  char *pam_service;
  char *pam_rhost;
  char *pam_tty;
  char *pam_user;

  int result = PAM_ABORT;
  int failopen = 1;

  struct idsa_pam_item idsa_pam_risk_table[3] = {
    {"availability=", IDSA_R_SUCCESS},
    {"confidentiality=", IDSA_R_UNKNOWN},
    {"integrity=", IDSA_R_UNKNOWN}
  };

  /* provisionally check for failclosed, later do the full parse */
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "failclosed") == 0) {
      failopen = 0;
    }
  }

  pam_service = NULL;
  if (pam_get_item(pamh, PAM_SERVICE, (const void **) (&pam_service)) != PAM_SUCCESS) {
    pam_service = NULL;
  }

  cn = idsa_open(pam_service ? pam_service : "pam", NULL, failopen ? IDSA_F_FAILOPEN : 0);
  if (cn == NULL) {
    return failopen ? PAM_IGNORE : PAM_ABORT;
  }

  if (pam_service == NULL) {
    idsa_scan(cn, "error-field", IDSA_PAM_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, "field", IDSA_T_STRING, "pam_service", NULL);
    idsa_close(cn);
    return failopen ? PAM_IGNORE : PAM_ABORT;
  }

  for (i = 0; i < argc; i++) {
    found = 0;
    for (j = 0; j < 3; j++) {
      len = strlen(idsa_pam_risk_table[j].r_name);
      if (strncmp(argv[i], idsa_pam_risk_table[j].r_name, len) == 0) {
	idsa_pam_risk_table[j].r_risk = idsa_risk_parse(argv[i] + len);
	found = 1;
      }
    }
    if ((found == 0) && (strcmp(argv[i], "failclosed") != 0)) {
      idsa_scan(cn, "error-usage", IDSA_PAM_SCHEME, 0, IDSA_R_NONE, IDSA_R_NONE, IDSA_R_MINOR, IDSA_ES, IDSA_T_STRING, IDSA_ES_USAGE, "usage", IDSA_T_STRING, argv[i], NULL);
      if (failopen == 0) {
	return PAM_ABORT;
      }
    }
  }

  pam_user = NULL;
  if (pam_get_user(pamh, (const char **) (&pam_user), NULL) != PAM_SUCCESS || pam_user == NULL) {
    idsa_scan(cn, "error-field", IDSA_PAM_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, "field", IDSA_T_STRING, "pam_user", NULL);
    idsa_close(cn);
    return failopen ? PAM_IGNORE : PAM_USER_UNKNOWN;
  }

  pwd = getpwnam(pam_user);
  if (pwd == NULL) {
    idsa_scan(cn, "error-field", IDSA_PAM_SCHEME, 0, IDSA_R_TOTAL, IDSA_R_NONE, IDSA_R_UNKNOWN, IDSA_ES, IDSA_T_STRING, IDSA_ES_SYSTEM, "field", IDSA_T_STRING, "pam_uid", "pam_user", IDSA_T_STRING, pam_user, NULL);
    idsa_close(cn);
    return failopen ? PAM_IGNORE : PAM_USER_UNKNOWN;
  }

  pam_rhost = NULL;
  pam_tty = NULL;
  if ((pam_get_item(pamh, PAM_RHOST, (const void **) (&pam_rhost)) != PAM_SUCCESS) || (pam_rhost == NULL) || (pam_rhost[0] == '\0')) {
    pam_rhost = NULL;
    if ((pam_get_item(pamh, PAM_TTY, (const void **) (&pam_tty)) != PAM_SUCCESS) || (pam_tty == NULL)) {
      pam_tty = ttyname(STDIN_FILENO);
    }
  }

  ev = idsa_event(cn);
  if (ev) {
    idsa_name(ev, "authenticate");
    idsa_scheme(ev, IDSA_PAM_SCHEME);

    idsa_risks(ev, 1, idsa_pam_risk_table[0].r_risk, idsa_pam_risk_table[1].r_risk, idsa_pam_risk_table[2].r_risk);
    idsa_add_string(ev, "pam_user", (char *) pam_user);
    idsa_add_set(ev, "pam_uid", IDSA_T_UID, &(pwd->pw_uid));

    if (pam_rhost != NULL) {
      idsa_add_string(ev, "pam_source", "pam_rhost");
      idsa_add_scan(ev, "pam_rhost", IDSA_T_HOST, pam_rhost);
    } else if (pam_tty != NULL) {
      idsa_add_string(ev, "pam_source", "pam_tty");
      idsa_add_string(ev, "pam_tty", pam_tty);
    } else {
      idsa_add_string(ev, "pam_source", "pam_none");
    }

    if (idsa_log(cn, ev) == IDSA_L_ALLOW) {
      result = PAM_SUCCESS;
    } else {
      result = PAM_AUTH_ERR;
    }
  } else {
    result = failopen ? PAM_IGNORE : PAM_ABORT;
  }

  idsa_close(cn);
  return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

/*************************************************************************/

#ifdef PAM_STATIC
struct pam_module _pam_idsa_modstruct = {
  "pam_idsa",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  NULL,
  NULL,
  NULL
};
#endif
