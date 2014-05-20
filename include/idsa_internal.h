#ifndef _IDSA_INTERNAL_
#define _IDSA_INTERNAL_

/* internal, variable API */

#include <stdarg.h>
#include <idsa.h>

#ifdef WANTS_PROF
#include <sys/times.h>
#endif

/* constants *************************************************************** */

#define IDSA_SOCKET      "/var/run/idsa"
#define IDSA_CONFIG      "/etc/idsa.d"

#ifdef __cplusplus
extern "C" {
#endif
/* maxima used inside below structures ************************************ */
#define IDSA_S_OFFSET (3*sizeof(unsigned int))
#define IDSA_M_UNITS  (IDSA_M_MESSAGE-IDSA_S_OFFSET)
#define IDSA_M_RISKS         3	/* number of risk types */
/* define the structures mentioned in idsa.h ****************************** */ struct idsa_unit {
    char u_name[IDSA_M_NAME];
    unsigned int u_type;
    char u_ptr[IDSA_M_LONG];
  };

  struct idsa_event {
    unsigned int e_magic;	/* magic */
    unsigned int e_size;	/* size to be written */
    unsigned int e_count;	/* count of units */
    char e_ptr[IDSA_M_UNITS];
  };

/* manipulation of units  ************************************************* */

  char *idsa_unit_name_get(IDSA_UNIT * u);
  int idsa_unit_name_set(IDSA_UNIT * u, char *n);

  unsigned int idsa_unit_type(IDSA_UNIT * u);
  int idsa_unit_size(IDSA_UNIT * u);

  IDSA_UNIT *idsa_unit_new(char *n, unsigned int t, char *s);
  IDSA_UNIT *idsa_unit_dup(IDSA_UNIT * u);
  void idsa_unit_copy(IDSA_UNIT * a, IDSA_UNIT * b);
  void idsa_unit_free(IDSA_UNIT * u);

  /* WARNING: comparisons should only be bitwise */

#define IDSA_COMPARE_EQUAL      0x01	/* a == b (strong equal) */
#define IDSA_COMPARE_INTERSECT  0x02	/* a n b != 0 (weak equal/weak diff) */
#define IDSA_COMPARE_DISJOINT   0x04	/* a n b = 0 (strong diff) */
#define IDSA_COMPARE_LESS       0x10	/* a < b */
#define IDSA_COMPARE_MORE       0x20	/* a > b */

  typedef int (*IDSA_FUNCTION_COMPARE) (IDSA_UNIT * a, IDSA_UNIT * b);
  typedef int (*IDSA_FUNCTION_CHECK) (IDSA_UNIT * u);
  typedef int (*IDSA_FUNCTION_GET) (IDSA_UNIT * u, void *p, int l);
  typedef int (*IDSA_FUNCTION_SET) (IDSA_UNIT * u, void *p);
  typedef int (*IDSA_FUNCTION_SCAN) (IDSA_UNIT * u, char *s);
  typedef int (*IDSA_FUNCTION_PRINT) (IDSA_UNIT * u, char *s, int l, int m);

  int idsa_unit_compare(IDSA_UNIT * a, IDSA_UNIT * b);
  int idsa_unit_check(IDSA_UNIT * u);
  int idsa_unit_get(IDSA_UNIT * u, void *p, int l);
  int idsa_unit_set(IDSA_UNIT * u, void *p);
  int idsa_unit_scan(IDSA_UNIT * u, char *s);
  int idsa_unit_print(IDSA_UNIT * u, char *s, int l, int m);

/* escaping of characters ************************************************* */

  int idsa_escape_unix(unsigned char *buffer, int len, int max);
  int idsa_escape_xml(unsigned char *buffer, int len, int max);

  int idsa_descape_unix(unsigned char *buffer, int len);

/* type related information *********************************************** */

  struct idsa_type_details;
  typedef struct idsa_type_details IDSA_TYPE_DETAILS;
  IDSA_TYPE_DETAILS *idsa_type_lookup(unsigned int t);

  unsigned int idsa_type_code(char *n);
  char *idsa_type_name(unsigned int t);
  int idsa_type_size(unsigned int t);

/*  unsigned int idsa_type_c(unsigned int t);*/

/* internal risk / cost stuff ********************************************* */

  unsigned int idsa_risk_parse(const char *s);
  int idsa_risk_put(unsigned int x, char *s, int l);
  int idsa_risk_cmp(unsigned int x, unsigned int y);

/* manipulation of events ************************************************* */

  IDSA_EVENT *idsa_event_new(unsigned int m);
  void idsa_event_clear(IDSA_EVENT * e, unsigned int m);
  void idsa_event_free(IDSA_EVENT * e);
  void idsa_event_copy(IDSA_EVENT * a, IDSA_EVENT * b);
  int idsa_event_concat(IDSA_EVENT * t, IDSA_EVENT * s);
  int idsa_event_check(IDSA_EVENT * e);

  unsigned int idsa_event_unitcount(IDSA_EVENT * e);

  IDSA_UNIT *idsa_event_unitbyname(IDSA_EVENT * e, char *n);
  IDSA_UNIT *idsa_event_unitbynumber(IDSA_EVENT * e, int n);

  IDSA_UNIT *idsa_event_setbynumber(IDSA_EVENT * e, int n, void *p);
  IDSA_UNIT *idsa_event_scanbynumber(IDSA_EVENT * e, int n, char *s);

  IDSA_UNIT *idsa_event_unitappend(IDSA_EVENT * e, IDSA_UNIT * u);
  IDSA_UNIT *idsa_event_setappend(IDSA_EVENT * e, char *n, unsigned int t, void *p);
  IDSA_UNIT *idsa_event_scanappend(IDSA_EVENT * e, char *n, unsigned int t, char *s);
  IDSA_UNIT *idsa_event_append(IDSA_EVENT * e, unsigned int t);

#include <stdio.h>

  int idsa_event_dump(IDSA_EVENT * e, FILE * f);

/* request and reply ******************************************************* */

#define IDSA_MAGIC_REQUEST 0x1d5a	/* report request */
#define IDSA_MAGIC_REPLY   0xa51d	/* reply */

#define IDSA_M_REQUEST          12	/* request required + 1 */
#define IDSA_M_REPLY             1	/* reply required + 1 */
#define IDSA_M_RESERVED         28	/* number of reserved fields +1 */
#define IDSA_M_UNKNOWN        1000	/* > max(REPLY,REQUEST,RESERVED) */

#define IDSA_Q_PID               0	/* "pid" */
#define IDSA_Q_UID               1	/* "uid" */
#define IDSA_Q_GID               2	/* "gid" */
#define IDSA_Q_TIME              3	/* "time" */
#define IDSA_Q_SERVICE           4	/* "service" */
#define IDSA_Q_HOST              5	/* "host" */
#define IDSA_Q_NAME              6	/* "name" */
#define IDSA_Q_SCHEME            7	/* "scheme" */
#define IDSA_Q_HONOUR            8	/* "honour" */
#define IDSA_Q_ARISK             9	/* "arisk: availability" */
#define IDSA_Q_CRISK            10	/* "crisk: confidentiality" */
#define IDSA_Q_IRISK            11	/* "irisk: integrity" */

#define IDSA_P_DENY             12	/* "deny" */

#define IDSA_O_REPEAT           13	/* "repeat" */
#define IDSA_O_REASON           14	/* "reason" */
#define IDSA_O_JOB              15	/* "job" */
#define IDSA_O_COMMENT          16	/* "comment" */
#define IDSA_O_PRERULE          17	/* "rule to filter out allowed" */
#define IDSA_O_PREFILE          18	/* "file" */
#define IDSA_O_FAILRULE         19	/* "run this in case of failure" */
#define IDSA_O_FAILFILE         20	/* "file" */
#define IDSA_O_AUTORULE         21	/* "rule to run in place of idsad" */
#define IDSA_O_AUTOFILE         22	/* "file" */
#define IDSA_O_BOTHRULE         23	/* "combine pre and fail filter" */
#define IDSA_O_BOTHFILE         24	/* "file" */
#define IDSA_O_SLEEP            25	/* "sleep" */
#define IDSA_O_STOP             26	/* "stop" */
#define IDSA_O_ENV              27	/* "env" */

  unsigned int idsa_resolve_code(char *n);
  char *idsa_resolve_name(unsigned int c);
  unsigned int idsa_resolve_type(unsigned int c, char *n);

  unsigned int idsa_resolve_request(unsigned int n);
  unsigned int idsa_resolve_reply(unsigned int n);

  unsigned int idsa_request_count();
  unsigned int idsa_reply_count();

  int idsa_request_init(IDSA_EVENT * e, char *service, char *group, char *name);
  int idsa_reply_init(IDSA_EVENT * e);

  int idsa_request_check(IDSA_EVENT * e);
  int idsa_reply_check(IDSA_EVENT * e);

  IDSA_UNIT *idsa_request_get(IDSA_EVENT * e, unsigned int c, char *n);
  IDSA_UNIT *idsa_reply_get(IDSA_EVENT * e, unsigned int c, char *n);

  int idsa_request_vset(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, va_list ap);
  int idsa_request_vscan(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, va_list ap);

  int idsa_request_set(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...);
  int idsa_request_scan(IDSA_EVENT * e, char *n, char *s, int f, unsigned ar, unsigned cr, unsigned ir, ...);

  int idsa_request_name(IDSA_EVENT * e, char *n);
  int idsa_request_scheme(IDSA_EVENT * e, char *n);
  int idsa_request_service(IDSA_EVENT * e, char *n);
  int idsa_request_risks(IDSA_EVENT * e, int f, unsigned a, unsigned c, unsigned i);
  int idsa_request_honour(IDSA_EVENT * e, int f);

  int idsa_request_pid(IDSA_EVENT * e, pid_t p);
  int idsa_request_uid(IDSA_EVENT * e, uid_t u);
  int idsa_request_gid(IDSA_EVENT * e, gid_t g);
  int idsa_request_time(IDSA_EVENT * e, time_t t);
  int idsa_request_host(IDSA_EVENT * e, char *h);

  int idsa_reply_allow(IDSA_EVENT * e);
  int idsa_reply_deny(IDSA_EVENT * e);
  int idsa_reply_result(IDSA_EVENT * e);
  int idsa_reply_repeat(IDSA_EVENT * e, int repeat);

/* raw io ***************************************************************** */

  int idsa_event_tobuffer(IDSA_EVENT * e, char *s, int l);
  int idsa_event_frombuffer(IDSA_EVENT * e, char *s, int l);

/* assorted output formats ************************************************ */

  struct idsa_print_handle;
  typedef struct idsa_print_handle IDSA_PRINT_HANDLE;

  IDSA_PRINT_HANDLE *idsa_print_format(char *n);
  IDSA_PRINT_HANDLE *idsa_print_parse(char *s);
  int idsa_print_do(IDSA_EVENT * e, IDSA_PRINT_HANDLE * ph, char *b, int l);
  void idsa_print_free(IDSA_PRINT_HANDLE * ph);

/* profiling stuff ******************************************************** */

#ifdef WANTS_PROF
  int idsa_prof(IDSA_CONNECTION * c, FILE * fp);
#endif

/* tokenizer ************************************************************** */

  struct idsa_mex_token {	/* token returned to caller */
    int t_id;			/* user assigned id */
    int t_type;			/* keyword, string, etc */
    char *t_buf;		/* copied payload */
    int t_len;			/* length of said payload */
    int t_line;			/* line on which it occurs */
    struct idsa_mex_token *t_next;	/* linked list for internal user only */
  };
  typedef struct idsa_mex_token IDSA_MEX_TOKEN;

  struct idsa_mex_keyword {	/* table to do keyword lookup */
    char *k_name;		/* string to compare against */
    int k_id;			/* id to be copied into t_id */
  };
  typedef struct idsa_mex_keyword IDSA_MEX_KEYWORD;

  struct idsa_mex_keychar {	/* table to do keychar lookup */
    char k_name;		/* string to compare against */
    int k_id;			/* id to be copied into t_id */
  };
  typedef struct idsa_mex_keychar IDSA_MEX_KEYCHAR;

  struct idsa_mex_state {	/* state */
    unsigned int m_unmap;	/* should unmap buffer on exit */
    unsigned int m_error;	/* saved error */
    unsigned int m_line;	/* line number */

    unsigned char *m_buf;	/* read buffer */
    unsigned int m_read;	/* number of bytes read into buffer */

    unsigned int m_lexed;	/* number of read bytes converted to tokens */

    IDSA_MEX_TOKEN *m_head;	/* list of available tokens */
    IDSA_MEX_TOKEN *m_this;	/* next available token */

    int m_keychars[256];	/* table for single character keywords */
    IDSA_MEX_KEYWORD *m_keywords;	/* array for all other keywords */
  };
  typedef struct idsa_mex_state IDSA_MEX_STATE;

#define IDSA_MEX_KEY       0x01
#define IDSA_MEX_WORD      0x02
#define IDSA_MEX_STRING    0x03

  IDSA_MEX_STATE *idsa_mex_fd(int fd);	/* parse fd */
  IDSA_MEX_STATE *idsa_mex_file(char *fname);	/* parse filename */
  IDSA_MEX_STATE *idsa_mex_buffer(char *buffer, int length);	/* parse string */

  int idsa_mex_close(IDSA_MEX_STATE * m);	/* zap the entire thing */

  int idsa_mex_tables(IDSA_MEX_STATE * m, IDSA_MEX_KEYCHAR * kc, IDSA_MEX_KEYWORD * kw);	/* load tables */

  IDSA_MEX_TOKEN *idsa_mex_get(IDSA_MEX_STATE * m);	/* grab the next token */
  IDSA_MEX_TOKEN *idsa_mex_peek(IDSA_MEX_STATE * m);	/* just sneak a look */
  void idsa_mex_unget(IDSA_MEX_STATE * m, IDSA_MEX_TOKEN * t);	/* oops, we did not need it */

  char *idsa_mex_error(IDSA_MEX_STATE * m);	/* display error string */
  void idsa_mex_dump(IDSA_MEX_STATE * m, FILE * f);	/* for debugging */

/* rule structures needed later ******************************************* */

  struct idsa_module;

  struct idsa_rule_test {	/* checks if a rule should trigger */
    struct idsa_module *t_module;	/* contains test function */
    struct idsa_rule_test *t_next;	/* linked list of rules for deletion */
    void *t_state;		/* type specific stuff */
  };
  typedef struct idsa_rule_test IDSA_RULE_TEST;

  struct idsa_rule_action {	/* does something if a rule triggered */
    struct idsa_module *a_module;	/* contains action function */
    struct idsa_rule_action *a_next;	/* per rule action list */
    void *a_state;
  };
  typedef struct idsa_rule_action IDSA_RULE_ACTION;

  struct idsa_rule_body {	/* rule body */
    char b_deny;		/* flag to allow or deny */
    char b_drop;		/* drop client */
    char b_continue;		/* continue evaluation of rules */
    int b_have;			/* number of items in array */
    struct idsa_rule_action **b_array;	/* list of actions */
  };
  typedef struct idsa_rule_body IDSA_RULE_BODY;

  struct idsa_rule_node {	/* graph of tests */
    struct idsa_rule_test *n_test;	/* test, if any */
    struct idsa_rule_node *n_true, *n_false;	/* which branch we should follow */
    struct idsa_rule_body *n_body;	/* what should be done */
    int n_count;		/* reference count */
  };
  typedef struct idsa_rule_node IDSA_RULE_NODE;

  struct idsa_rule_local {
    int l_result;

    IDSA_EVENT *l_request;
    IDSA_EVENT *l_reply;

    IDSA_RULE_NODE *l_node;
  };
  typedef struct idsa_rule_local IDSA_RULE_LOCAL;

  struct idsa_rule_chain {
    IDSA_RULE_NODE *c_nodes;
    IDSA_RULE_TEST *c_tests;
    IDSA_RULE_ACTION *c_actions;

    struct idsa_module *c_modules;	/* dynamic modules */

    int c_nodecount;		/* number of nodes in flight */
    int c_testcount;		/* number of tests */
    int c_actioncount;		/* number of actions */
    int c_modulecount;		/* number of modules loaded */
    int c_rulecount;		/* number of rules */

    int c_flags;

    int c_error;
    int c_fresh;
    IDSA_EVENT *c_event;

    char *c_chain;		/* chain name */
  };
  typedef struct idsa_rule_chain IDSA_RULE_CHAIN;

#define IDSA_CHAIN_OK    0
#define IDSA_CHAIN_AGAIN 1
#define IDSA_CHAIN_DROP  2

/* module interface *********************************************************/

#define IDSA_MODULE_INTERFACE_VERSION 0

  typedef void *(*IDSA_MODULE_GLOBAL_START) (IDSA_RULE_CHAIN * c);
  typedef int (*IDSA_MODULE_GLOBAL_BEFORE) (IDSA_RULE_CHAIN * c, void *g, IDSA_EVENT * q);
  typedef int (*IDSA_MODULE_GLOBAL_AFTER) (IDSA_RULE_CHAIN * c, void *g, IDSA_EVENT * q, IDSA_EVENT * p);
  typedef void (*IDSA_MODULE_GLOBAL_STOP) (IDSA_RULE_CHAIN * c, void *g);


  typedef void *(*IDSA_MODULE_TEST_START) (IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g);
  typedef int (*IDSA_MODULE_TEST_CACHE) (IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t);
  typedef int (*IDSA_MODULE_TEST_DO) (IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q);	/* return true, false and maybe stall ? */
  typedef void (*IDSA_MODULE_TEST_STOP) (IDSA_RULE_CHAIN * c, void *g, void *t);


  typedef void *(*IDSA_MODULE_ACTION_START) (IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g);
  typedef int (*IDSA_MODULE_ACTION_CACHE) (IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *a);
  typedef int (*IDSA_MODULE_ACTION_DO) (IDSA_RULE_CHAIN * c, void *g, void *a, IDSA_EVENT * q, IDSA_EVENT * p);
  /* return mask of deny, drop */
  typedef void (*IDSA_MODULE_ACTION_STOP) (IDSA_RULE_CHAIN * c, void *g, void *a);

  struct idsa_module {
    int m_version;
    char m_name[IDSA_M_NAME];

    struct idsa_module *m_next;

    void *m_handle;		/* nonzero for dynamically loaded libs */
    void *m_state;		/* global module state */

    IDSA_MODULE_GLOBAL_START global_start;
    IDSA_MODULE_GLOBAL_BEFORE global_before;
    IDSA_MODULE_GLOBAL_AFTER global_after;
    IDSA_MODULE_GLOBAL_STOP global_stop;

    IDSA_MODULE_TEST_START test_start;
    IDSA_MODULE_TEST_CACHE test_cache;
    IDSA_MODULE_TEST_DO test_do;
    IDSA_MODULE_TEST_STOP test_stop;

    IDSA_MODULE_ACTION_START action_start;
    IDSA_MODULE_ACTION_CACHE action_cache;
    IDSA_MODULE_ACTION_DO action_do;
    IDSA_MODULE_ACTION_STOP action_stop;
  };
  typedef struct idsa_module IDSA_MODULE;

  int idsa_module_start_global(IDSA_RULE_CHAIN * c);
  int idsa_module_before_global(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l);
  int idsa_module_after_global(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l);
  void idsa_module_stop_global(IDSA_RULE_CHAIN * c);

  IDSA_RULE_TEST *idsa_module_start_test(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, char *n);
  int idsa_module_do_test(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t, IDSA_EVENT * q);
  void idsa_module_stop_test(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t);

  IDSA_RULE_ACTION *idsa_module_start_action(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, char *n);
  int idsa_module_do_action(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a, IDSA_EVENT * q, IDSA_EVENT * p);
  void idsa_module_stop_action(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a);

/* dyamic module loader *************************************************** */

  IDSA_MODULE *idsa_module_load(IDSA_RULE_CHAIN * c, char *n);

/* module prototypes (needed if compiled statically *********************** */

  IDSA_MODULE *idsa_module_load_counter(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_default(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_diff(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_example1(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_example2(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_exists(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_interactive(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_keep(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_log(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_pipe(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_regex(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_sad(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_send(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_time(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_timer(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_true(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_truncated(IDSA_RULE_CHAIN * c);
  IDSA_MODULE *idsa_module_load_type(IDSA_RULE_CHAIN * c);

/* support functions for module writers *********************************** */

  int idsa_support_eot(IDSA_RULE_CHAIN * c, IDSA_MEX_STATE * m);

/* allocation ************************************************************* */

  IDSA_RULE_CHAIN *idsa_chain_new();
  int idsa_chain_free(IDSA_RULE_CHAIN * c);

  char *idsa_chain_getname(IDSA_RULE_CHAIN * c);
  void idsa_chain_setname(IDSA_RULE_CHAIN * c, char *name);

  IDSA_RULE_ACTION *idsa_action_new(IDSA_RULE_CHAIN * c);
  int idsa_action_free(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a);

  IDSA_RULE_BODY *idsa_body_new(IDSA_RULE_CHAIN * c);
  void idsa_body_add(IDSA_RULE_CHAIN * c, IDSA_RULE_BODY * b, IDSA_RULE_ACTION * a);
  int idsa_body_free(IDSA_RULE_CHAIN * c, IDSA_RULE_BODY * b);

  IDSA_RULE_NODE *idsa_node_new(IDSA_RULE_CHAIN * c);
  int idsa_node_free(IDSA_RULE_CHAIN * c, IDSA_RULE_NODE * n);

  IDSA_RULE_TEST *idsa_test_new(IDSA_RULE_CHAIN * c);
  int idsa_test_free(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t);

  IDSA_RULE_LOCAL *idsa_local_new(IDSA_RULE_CHAIN * c);
  void idsa_local_free(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l);

  IDSA_MODULE *idsa_module_new_version(IDSA_RULE_CHAIN * c, char *name, int ver);
  IDSA_MODULE *idsa_module_new(IDSA_RULE_CHAIN * c, char *name);
  void idsa_module_free(IDSA_RULE_CHAIN * c, IDSA_MODULE * m);

/* rule evaluation ******************************************************** */

  int idsa_local_init(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l, IDSA_EVENT * q, IDSA_EVENT * p);
  int idsa_local_quit(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l);	/* to unlock */

  IDSA_RULE_CHAIN *idsa_chain_start(IDSA_EVENT * e, int flags);
  int idsa_chain_run(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l);
  int idsa_chain_stop(IDSA_RULE_CHAIN * c);

  int idsa_chain_failure(IDSA_RULE_CHAIN * c);	/* is there a serious error */
  int idsa_chain_notice(IDSA_RULE_CHAIN * c);	/* a message is available */
  int idsa_chain_reset(IDSA_RULE_CHAIN * c);	/* reset the message flag */

/* parser related stuff *****************************************************/

  IDSA_RULE_CHAIN *idsa_parse_fd(IDSA_EVENT * e, int fd, int flags);
  IDSA_RULE_CHAIN *idsa_parse_file(IDSA_EVENT * e, char *fname, int flags);
  IDSA_RULE_CHAIN *idsa_parse_buffer(IDSA_EVENT * e, char *buffer, int len, int flags);

#define IDSA_PARSE_COLON           0x01	/* : */
#define IDSA_PARSE_SCOLON          0x02	/* ; */
#define IDSA_PARSE_OPEN            0x03	/* ( */
#define IDSA_PARSE_CLOSE           0x04	/* ) */
#define IDSA_PARSE_NOT             0x05	/* ! */
#define IDSA_PARSE_AND             0x06	/* & */
#define IDSA_PARSE_OR              0x07	/* | */
#define IDSA_PARSE_COMMA           0x08	/* , */
#define IDSA_PARSE_MOD             0x09	/* % */

#define IDSA_PARSE_ALLOW           0x10	/* allow */
#define IDSA_PARSE_DENY            0x11	/* deny */
#define IDSA_PARSE_CONTINUE        0x12	/* continue */
#define IDSA_PARSE_DROP            0x13	/* drop */

  void idsa_chain_error_token(IDSA_RULE_CHAIN * c, IDSA_MEX_TOKEN * t);
  void idsa_chain_error_mex(IDSA_RULE_CHAIN * c, IDSA_MEX_STATE * m);

  void idsa_chain_error_system(IDSA_RULE_CHAIN * c, int e, char *s, ...);
  void idsa_chain_error_internal(IDSA_RULE_CHAIN * c, char *s, ...);
  void idsa_chain_error_usage(IDSA_RULE_CHAIN * c, char *s, ...);
  void idsa_chain_error_malloc(IDSA_RULE_CHAIN * c, int bytes);

/****************************************************************************/

  void idsa_scheme_error_system(IDSA_EVENT * evt, int err, char *s, ...);
  void idsa_scheme_error_internal(IDSA_EVENT * evt, char *s, ...);
  void idsa_scheme_error_usage(IDSA_EVENT * evt, char *s, ...);
  void idsa_scheme_error_malloc(IDSA_EVENT * evt, int bytes);

  void idsa_scheme_verror_system(IDSA_EVENT * evt, int err, char *s, va_list ap);
  void idsa_scheme_verror_internal(IDSA_EVENT * evt, char *s, va_list ap);
  void idsa_scheme_verror_usage(IDSA_EVENT * evt, char *s, va_list ap);

/****************************************************************************/

  unsigned int idsa_syspri2a(int pri);
  unsigned int idsa_syspri2c(int pri);
  unsigned int idsa_syspri2i(int pri);
  char *idsa_syspri2severity(int pri);

/****************************************************************************/

#ifdef __cplusplus
}
#endif
#endif
