/* triggers for certain times */
/* usage: %time [utc|local] [sec|min|hour|mday|mon|wday|yday] value[,value] */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/types.h>

#include <idsa_internal.h>

/****************************************************************************/

static char *time_components[] = { "sec", "min", "hou", "mda", "yda", "wda", "mon", NULL };
static int time_sizes[] = { 62, 60, 24, 32, 366, 7, 12, 0 };

static char *time_wdays[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat", NULL };
static char *time_mons[] = { "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
  "nov", "dec", NULL
};

struct time_data {
  int t_utc;
  int t_component;
  int t_size;
  unsigned char *t_bitmap;
};

static int time_position = 0;

/****************************************************************************/

#ifdef TRACE
void time_dump_bitmap(struct time_data *data, FILE * fp)
{
  int i;
  int bytes;

  bytes = (data->t_size + 7) / 8;
  for (i = 0; i < bytes; i++) {
    fprintf(fp, "%02x", data->t_bitmap[i]);
  }
}
#endif

static int time_index(IDSA_RULE_CHAIN * c, char *string, int component)
{
  int result;

#ifdef TRACE
  fprintf(stderr, "mod_time_index: attempting to look up %s:%d\n", string, component);
#endif

  switch (component) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
    result = atoi(string);
    break;
  case 5:
    result = 0;
    while ((time_wdays[result])
	   && (strncasecmp(time_wdays[result], string, 3))) {
      result++;
    }
    if (time_wdays[result] == NULL) {
      idsa_chain_error_usage(c, "unknown month \"%s\" for time module", string);
      return -1;
    }
    break;
  case 6:
    result = 0;
    while ((time_mons[result])
	   && (strncasecmp(time_mons[result], string, 3))) {
      result++;
    }
    if (time_mons[result] == NULL) {
      idsa_chain_error_usage(c, "unknown month \"%s\" for time module", string);
      return -1;
    }
    break;
  default:
    idsa_chain_error_usage(c, "unknown field \"%s\" for time module", string);
    return -1;
    break;
  }

  if (result >= time_sizes[component]) {
    idsa_chain_error_usage(c, "value %d for field \"%s\" is out of range", result, string);
    return -1;
  }

  return result;
}

/****************************************************************************/
/* Does       : Create a test instance                                      */

static void *time_test_start(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g)
{
  struct time_data *result;
  IDSA_MEX_TOKEN *token;
  int utc;
  int component;
  int size;
  int bytes;
  int index;
  unsigned char *bitmap;
  int i;

  if (time_position == 0) {
    /* WARNING: safety issues if concurrent assignments don't yield the consistent value */
    time_position = idsa_resolve_request(IDSA_Q_TIME);
  }

  token = idsa_mex_get(m);
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  if (!strcmp(token->t_buf, "utc")) {
    utc = 1;
    token = idsa_mex_get(m);
  } else {
    utc = 0;
    if (!strcmp(token->t_buf, "local")) {
      token = idsa_mex_get(m);
    }
  }
  if (token == NULL) {
    idsa_chain_error_mex(c, m);
    return NULL;
  }

  component = 0;
  while ((time_components[component])
	 && (strncmp(time_components[component], token->t_buf, 3))) {
    component++;
  }

  if (time_components[component] == NULL) {
    idsa_chain_error_usage(c, "unknown time field \"%s\" for time module on line %d", token->t_buf, token->t_line);
    return NULL;
  }

  size = time_sizes[component];
  bytes = (size + 7) / 8;

  bitmap = malloc(sizeof(char) * bytes);
  if (bitmap == NULL) {
    idsa_chain_error_malloc(c, sizeof(char) * bytes);
    return NULL;
  }
  for (i = 0; i < bytes; i++) {
    bitmap[i] = 0;
  }

  do {

    token = idsa_mex_get(m);
    if (token == NULL) {
      idsa_chain_error_mex(c, m);
      free(bitmap);
      return NULL;
    }

    index = time_index(c, token->t_buf, component);
    if (index < 0) {
      free(bitmap);
      return NULL;
    }
    bitmap[index / 8] |= (1 << index % 8);

    token = idsa_mex_get(m);
    if (token) {
      if (token->t_id != IDSA_PARSE_COMMA) {
	idsa_mex_unget(m, token);
	token = NULL;
      }
    }

  } while (token != NULL);

  result = malloc(sizeof(struct time_data));
  if (result == NULL) {
    idsa_chain_error_malloc(c, sizeof(struct time_data));
    free(bitmap);
    return NULL;
  }

  result->t_utc = utc;
  result->t_component = component;
  result->t_size = size;
  result->t_bitmap = bitmap;

#ifdef TRACE
  fprintf(stderr, "mod_time_start: bitmap is 0x");
  time_dump_bitmap(result, stderr);
  fprintf(stderr, "\n");
#endif

  return result;
}

/****************************************************************************/
/* Does       : The actual work of testing an event                         */
/* Parameters : g - global state: here always NULL, t - test state: the     */
/*              pointer returned by test_start()                            */
/* Returns    : 1 on match, 0 if not matched                                */

static int time_test_do(IDSA_RULE_CHAIN * c, void *g, void *t, IDSA_EVENT * q)
{
  struct time_data *data;
  struct tm *time_struct;
  time_t time_type;
  IDSA_UNIT *time_unit;
  int value;

  data = (struct time_data *) t;
  time_unit = idsa_event_unitbynumber(q, time_position);

  if (time_unit == NULL) {
    return 0;
  }

  if (idsa_unit_get(time_unit, &time_type, sizeof(time_type)) != sizeof(time_type)) {
    return 0;
  }

  if (data->t_utc) {
    time_struct = gmtime(&time_type);
  } else {
    time_struct = localtime(&time_type);
  }

  switch (data->t_component) {
  case 0:
    value = time_struct->tm_sec;
    break;
  case 1:
    value = time_struct->tm_min;
    break;
  case 2:
    value = time_struct->tm_hour;
    break;
  case 3:
    value = time_struct->tm_mday;
    break;
  case 4:
    value = time_struct->tm_yday;
    break;
  case 5:
    value = time_struct->tm_wday;
    break;
  case 6:
    value = time_struct->tm_mon;
    break;
  default:
    return 0;
    break;
  }

  if (value >= data->t_size) {
    return 0;
  }
#ifdef TRACE
  fprintf(stderr, "mod_time: about to compare %d/%d against 0x", data->t_component, value);
  time_dump_bitmap(data, stderr);
  fprintf(stderr, "\n");
#endif

  if (data->t_bitmap[value / 8] & (1 << (value % 8))) {
    return 1;
  }

  return 0;
}

/****************************************************************************/
/* Does       : Deallocate all resources associated with a test. In case    */
/*              of persistence this could save state to file                */

static void time_test_stop(IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct time_data *result;

  result = (struct time_data *) t;

  if (result != NULL) {
    if (result->t_bitmap != NULL) {
      free(result->t_bitmap);
      result->t_bitmap = NULL;
    }
    free(result);
  }
}

/****************************************************************************/
/* Does       : Compares a test about to be created against one already     */
/*              set up to check if they are smaller (-1), equal (0) or      */
/*              greater (1) to avoid creating identical instances.          */

static int time_test_cache(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, void *g, void *t)
{
  struct time_data *alpha, *beta;
  int result = 0;

  alpha = t;
  beta = time_test_start(m, c, g);

  if (beta == NULL) {
    return -1;
  }

  if (alpha->t_component != beta->t_component) {
    result = (alpha->t_component > beta->t_component) ? 1 : -1;
  } else {
    result = memcmp(alpha->t_bitmap, beta->t_bitmap, (alpha->t_size + 7) / 8);
  }

  time_test_stop(c, g, beta);
  return result;
}

/****************************************************************************/
/* Does       : Registers a new module. Usually this function is the same   */
/*              across modules, except for name changes                     */
/* Returns    : Pointer to module structure, or NULL on failure             */

IDSA_MODULE *idsa_module_load_time(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *result;

  result = idsa_module_new_version(c, "time", IDSA_MODULE_INTERFACE_VERSION);
  if (result) {
    result->test_start = &time_test_start;
    result->test_cache = &time_test_cache;
    result->test_do = &time_test_do;
    result->test_stop = &time_test_stop;
  }

  return result;
}
