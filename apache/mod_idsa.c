/* This work has been written by Marc Welz but is based on the example
 * modules shipped with apache 1.3.11. The examples shipped with the
 * notice reproduced below.
 */

/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/* #define USE_CLF */

#include <idsa_internal.h>

#ifndef USE_CLF
#include <idsa_schemes.h>
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

module idsa_module;

typedef struct {
  unsigned int arisk, crisk, irisk;
} idsa_state;

int idsa_enabled = 0;
IDSA_CONNECTION *idsa_connection = NULL;

#define MODIDSA_PARM_ERROR    "mod_idsa: paramter or state variable unavailable"
#define MODIDSA_CONNECT_ERROR "mod_idsa: unable to open IDS/A connection"


static void *create_idsa(pool * p, char *d)
{
  idsa_state *st = (idsa_state *) ap_palloc(p, sizeof(idsa_state));

  if (st) {
    st->arisk = IDSA_R_UNKNOWN;
    st->crisk = IDSA_R_UNKNOWN;
    st->irisk = IDSA_R_UNKNOWN;
  }

  return (void *) st;
}

/* called on parsing keyword */
static const char *set_idsa(cmd_parms * parms, void *s, int arg)
{
  if (arg) {
    idsa_enabled = 1;
  }
  return NULL;
}

static const char *set_arisk(cmd_parms * parms, void *s, char *arg)
{
  idsa_state *st = (idsa_state *) s;

  if (st && arg) {
    st->arisk = idsa_risk_parse(arg);
    return NULL;
  }
  return MODIDSA_PARM_ERROR;
}

static const char *set_crisk(cmd_parms * parms, void *s, char *arg)
{
  idsa_state *st = (idsa_state *) s;
  if (st && arg) {
    st->crisk = idsa_risk_parse(arg);
    return NULL;
  }
  return MODIDSA_PARM_ERROR;
}

static const char *set_irisk(cmd_parms * parms, void *s, char *arg)
{
  idsa_state *st = (idsa_state *) s;
  if (st && arg) {
    st->irisk = idsa_risk_parse(arg);
    return NULL;
  }
  return MODIDSA_PARM_ERROR;
}

static const command_rec cmds_idsa[] = {
  {"IdsaLog", set_idsa, NULL, RSRC_CONF, FLAG,
   "enable IDS/A interface, either on or off"},
  {"IdsaAvailability", set_arisk, NULL, OR_AUTHCFG, TAKE1,
   "risk to availability"},
  {"IdsaConfidentiality", set_crisk, NULL, OR_AUTHCFG, TAKE1,
   "risk to confidentiality"},
  {"IdsaIntegrity", set_irisk, NULL, OR_AUTHCFG, TAKE1,
   "risk to integrity"},
  {NULL}
};

#ifdef USE_FNL
#define MAX_LEVEL 5
struct functionality_idsa {
  char *f_method;
  unsigned int f_level;
} functionality_table[] = {
  {
  "GET", 0}, {
  "HEAD", 0}, {
  "POST", 1}, {
  "OPTIONS", 2}, {
  "PROPFIND", 2}, {
  "TRACE", 2}, {
  "MKCOL", 3}, {
  "LOCK", 3}, {
  "UNLOCK", 3}, {
  "PROPPATCH", 3}, {
  "PUT", 4}, {
  "DELETE", 4}, {
  "COPY", 4}, {
  "MOVE", 4}, {
  NULL, MAX_LEVEL}
};

static int get_level(char *method)
{
  int i;
  for (i = 0; functionality_table[i].f_method && strcmp(method, functionality_table[i].f_method); i++);

  return functionality_table[i].f_level;
}
#endif

static int access_idsa(request_rec * r)
{
  char *agent, *referer, *method, *protocol, *hostname;
  IDSA_EVENT *e;
  idsa_state *st = ap_get_module_config(r->per_dir_config, &idsa_module);

  if ((idsa_enabled == 0) || (idsa_connection == NULL))
    return DECLINED;

  e = idsa_event(idsa_connection);
  idsa_name(e, "request");
  idsa_scheme(e, "httpd");

  if (st) {
    idsa_risks(e, 1, st->arisk, st->crisk, st->irisk);
  }
  (const char *) method = r->method;
  if (method) {
    idsa_add_string(e, "method", method);
#ifdef USE_FNL
    idsa_add_integer(e, IDSA_FNL_LEVEL, get_level(method));
    idsa_add_integer(e, IDSA_FNL_MAX, MAX_LEVEL);
#endif
  }
  (const char *) protocol = r->protocol;
  if (protocol) {
    idsa_add_string(e, "protocol", protocol);
  }
  (const char *) hostname = r->hostname;
  if (hostname) {
#ifdef USE_CLF
    idsa_add_string(e, IDSA_CLF_REMOTEHOST, hostname);
#else
    idsa_add_string(e, "hostname", hostname);
#endif
  }
  if (r->unparsed_uri) {
#ifdef USE_CLF
    idsa_add_string(e, IDSA_CLF_REQUEST, r->unparsed_uri);
#else
    idsa_add_string(e, "url", r->unparsed_uri);
#endif
  }
  if (r->filename) {
    idsa_add_scan(e, "filename", IDSA_T_FILE, r->filename);
  }
  if (r->connection->remote_ip) {
    idsa_add_scan(e, "ip4src", IDSA_T_ADDR, r->connection->remote_ip);
  }
  /* some of the older 1.3.x apache versions don't have this field */
  if (r->connection->local_ip) {
    idsa_add_scan(e, "ip4dst", IDSA_T_ADDR, r->connection->local_ip);
  }
  (const char *) agent = ap_table_get(r->headers_in, "User-Agent");
  if (agent) {
    idsa_add_string(e, "agent", agent);
  }
  (const char *) referer = ap_table_get(r->headers_in, "Referer");
  if (referer) {
    idsa_add_string(e, "referer", referer);
  }
  if (idsa_log(idsa_connection, e) == IDSA_L_ALLOW) {
    return DECLINED;
  }
  return HTTP_FORBIDDEN;
}

static void start_idsa(server_rec * s, pool * p)
{
  if (idsa_enabled) {
    idsa_connection = idsa_open("apache", NULL, IDSA_F_UPLOAD);
    if (idsa_connection == NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, s, MODIDSA_CONNECT_ERROR);
    }
  }
}

static void fork_idsa(server_rec * s, pool * p)
{
  if (idsa_enabled) {
    idsa_reset(idsa_connection);
  }
}

static void exit_idsa(server_rec * s, pool * p)
{
  if (idsa_connection) {
    idsa_close(idsa_connection);
    idsa_connection = NULL;
  }
}

module idsa_module = {
  STANDARD_MODULE_STUFF,
  start_idsa,			/* initializer */
  create_idsa,			/* create per-dir config */
  NULL,				/* merge per-dir config */
  NULL,				/* server config */
  NULL,				/* merge server config */
  cmds_idsa,			/* command table */
  NULL,				/* handlers */
  NULL,				/* filename translation */
  NULL,				/* check_user_id */
  NULL,				/* check auth */
  access_idsa,			/* check access */
  NULL,				/* type_checker */
  NULL,				/* fixups */
  NULL,				/* logger */
  NULL,				/* header parser */
  fork_idsa,			/* child_init */
  exit_idsa,			/* child_exit */
  NULL				/* post read-request */
};
