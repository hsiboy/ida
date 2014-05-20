#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef DLDIR
#include <dlfcn.h>
#endif

#include <idsa_internal.h>

IDSA_MODULE *(*idsa_static_modules[]) (IDSA_RULE_CHAIN * c) = {
#ifdef FIXEDMODULES
  FIXEDMODULES
#else
  NULL
#endif
};

static int idsa_module_prepare(IDSA_RULE_CHAIN * c, IDSA_MODULE * m);

/****************************************************************************/

int idsa_module_start_global(IDSA_RULE_CHAIN * c)
{
  int i;
  IDSA_MODULE *module;

  i = 0;
  while (idsa_static_modules[i]) {
    module = (*idsa_static_modules[i]) (c);
    if (module) {
      idsa_module_prepare(c, module);
    } else {
      idsa_chain_error_internal(c, "unable to initialize static module");
    }
    i++;
  }

  return c->c_error;
}

int idsa_module_before_global(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l)
{
  IDSA_MODULE *mi;
  int result = 0;

  for (mi = c->c_modules; mi != NULL; mi = mi->m_next) {
    if (mi->global_before) {
      result += (*mi->global_before) (c, mi->m_state, l->l_request);
    }
  }

  return result;
}

int idsa_module_after_global(IDSA_RULE_CHAIN * c, IDSA_RULE_LOCAL * l)
{
  IDSA_MODULE *mi;
  int result = 0;

  for (mi = c->c_modules; mi != NULL; mi = mi->m_next) {
    if (mi->global_after) {
      result += (*mi->global_after) (c, mi->m_state, l->l_request, l->l_reply);
    }
  }

  return result;
}

/****************************************************************************/
/* Does       : deallocate module handles and call their shutdown function  */

void idsa_module_stop_global(IDSA_RULE_CHAIN * c)
{
  IDSA_MODULE *mi, *mj;

  if (c) {
    mi = c->c_modules;
    while (mi) {
      mj = mi;
      mi = mi->m_next;

      if (mj->m_state && mj->global_stop) {
	(*mj->global_stop) (c, mj->m_state);
	mj->m_state = NULL;
      }
#ifdef DLDIR
      if (mj->m_handle) {
	dlclose(mj->m_handle);
	mj->m_handle = NULL;
      }
#endif

      idsa_module_free(c, mj);
    }
    c->c_modules = NULL;
  }
}

/****************************************************************************/

IDSA_RULE_TEST *idsa_module_start_test(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, char *n)
{
  IDSA_RULE_TEST *ti, *result;
  IDSA_MODULE *mi, *module;
  IDSA_MEX_TOKEN *rewind;

  ti = c->c_tests;
  module = NULL;
  result = NULL;
  rewind = idsa_mex_peek(m);

  while (ti) {
    if (strcmp(n, ti->t_module->m_name)) {
#ifdef DEBUG
      fprintf(stderr, "idsa_module_start_test(): different modules %s != %s\n", n, ti->t_module->m_name);
#endif
      ti = ti->t_next;
    } else {
      module = ti->t_module;
      if ((*module->test_cache) (m, c, module->m_state, ti->t_state) == 0) {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_test(): cache hit for %s\n", n);
#endif
	result = ti;
	ti = NULL;
      } else {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_test(): cache miss for %s, rewinding to %s\n", n, rewind->t_buf);
#endif
	idsa_mex_unget(m, rewind);
	ti = ti->t_next;
      }
    }
  }

  /* found a match, no need to duplicate test */
  if (result) {
    return result;
  }

  /* could not discover module from test cache, look up in list */
  if (!module) {
    mi = c->c_modules;
    while (mi) {
      if (!strcmp(mi->m_name, n)) {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_test(): found module using plan B\n");
#endif
	module = mi;
	mi = NULL;
      } else {
	mi = mi->m_next;
      }
    }
  }

  /* plan B did not work either, need to load it */
  if (!module) {
    module = idsa_module_load(c, n);
    if (!module) {
      return NULL;
    }
    if (idsa_module_prepare(c, module)) {
      return NULL;
    }
  }

  if (!module->test_start) {
    idsa_chain_error_usage(c, "module <%s> does not implement tests", n);
    return NULL;
  }

  result = idsa_test_new(c);
  if (!result) {
    return NULL;
  }

  result->t_module = module;
  result->t_state = (*module->test_start) (m, c, module->m_state);

  /* on error destroy test */
  if (c->c_error) {
    idsa_module_stop_test(c, result);
    return NULL;
  }

  /* add to linked list */
  result->t_next = c->c_tests;
  c->c_tests = result;

  return result;
}

int idsa_module_do_test(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t, IDSA_EVENT * q)
{
  if (t->t_module->test_do) {
    return (*t->t_module->test_do) (c, t->t_module->m_state, t->t_state, q);
  }

  return 0;
}

void idsa_module_stop_test(IDSA_RULE_CHAIN * c, IDSA_RULE_TEST * t)
{
  IDSA_MODULE *module;

  if (t) {
    module = t->t_module;
    if (t->t_state && module->test_stop) {
      (*module->test_stop) (c, module->m_state, t->t_state);
      t->t_state = NULL;
    }
    t->t_next = NULL;
    idsa_test_free(c, t);
  }
}

/****************************************************************************/

IDSA_RULE_ACTION *idsa_module_start_action(IDSA_MEX_STATE * m, IDSA_RULE_CHAIN * c, char *n)
{
  IDSA_RULE_ACTION *ai, *result;
  IDSA_MODULE *mi, *module;
  IDSA_MEX_TOKEN *rewind;

  ai = c->c_actions;
  module = NULL;
  result = NULL;
  rewind = idsa_mex_peek(m);

  while (ai) {
    if (strcmp(n, ai->a_module->m_name)) {
#ifdef DEBUG
      fprintf(stderr, "idsa_module_start_action(): different modules %s != %s\n", n, ai->a_module->m_name);
#endif
      ai = ai->a_next;
    } else {
      module = ai->a_module;
      if ((*module->action_cache) (m, c, module->m_state, ai->a_state) == 0) {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_action(): cache hit for %s\n", n);
#endif
	result = ai;
	ai = NULL;
      } else {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_action(): cache miss for %s, rewinding to %s\n", n, rewind->t_buf);
#endif
	idsa_mex_unget(m, rewind);
	ai = ai->a_next;
      }
    }
  }

  /* found a match, no need to duplicate test */
  if (result) {
    return result;
  }

  /* could not discover module from test cache, look up in list */
  if (!module) {
    mi = c->c_modules;
    while (mi) {
      if (!strcmp(mi->m_name, n)) {
#ifdef DEBUG
	fprintf(stderr, "idsa_module_start_action(): found module using plan B\n");
#endif
	module = mi;
	mi = NULL;
      } else {
	mi = mi->m_next;
      }
    }
  }

  /* plan B did not work either, need to load it */
  if (!module) {
    module = idsa_module_load(c, n);
    if (!module) {
      return NULL;
    }
    if (idsa_module_prepare(c, module)) {
      return NULL;
    }
  }

  if (!module->action_start) {
    idsa_chain_error_usage(c, "module <%s> does not implement actions", n);
    return NULL;
  }

  result = idsa_action_new(c);
  if (!result) {
    return NULL;
  }

  result->a_module = module;
  result->a_state = (*module->action_start) (m, c, module->m_state);

  /* on error destroy test */
  if (c->c_error) {
    idsa_module_stop_action(c, result);
    return NULL;
  }

  /* add to linked list */
  result->a_next = c->c_actions;
  c->c_actions = result;

  return result;
}

int idsa_module_do_action(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a, IDSA_EVENT * q, IDSA_EVENT * p)
{
  if (a->a_module->action_do) {
#ifdef DEBUG
    fprintf(stderr, "idsa_module_do_action(): doing %s\n", a->a_module->m_name);
#endif
    return (*a->a_module->action_do) (c, a->a_module->m_state, a->a_state, q, p);
  }

  return 0;
}

void idsa_module_stop_action(IDSA_RULE_CHAIN * c, IDSA_RULE_ACTION * a)
{
  IDSA_MODULE *module;

  if (a) {
    module = a->a_module;
    if (a->a_state && module->action_stop) {
      (*module->action_stop) (c, module->m_state, a->a_state);
      a->a_state = NULL;
    }
    a->a_next = NULL;
    idsa_action_free(c, a);
  }
}


/****************************************************************************/

#define BUFFER_DL 1024

IDSA_MODULE *idsa_module_load(IDSA_RULE_CHAIN * c, char *n)
{
#ifndef DLDIR
  idsa_chain_error_internal(c, "dynamic module loading not implemented");
  return NULL;
#else

  IDSA_MODULE *result;
  char buffer[BUFFER_DL];
  void *handle;
  char *error;
  IDSA_MODULE *(*loader) (IDSA_RULE_CHAIN *);

  if (strchr(n, '/')) {
    idsa_chain_error_usage(c, "module %s may not contain a path component");
    return NULL;
  }

  snprintf(buffer, BUFFER_DL - 1, "%s/mod_%s.so", DLDIR, n);
  buffer[BUFFER_DL - 1] = '\0';

#ifdef DEBUG
  fprintf(stderr, "idsa_module_load(): attempting to load module %s from %s\n", n, buffer);
#endif

  handle = dlopen(buffer, RTLD_NOW);
  if (handle == NULL) {
    error = dlerror();
    idsa_chain_error_internal(c, "unable to load %s: %s", buffer, error ? error : "unknown error");
    return NULL;
  }

  snprintf(buffer, BUFFER_DL - 1, "idsa_module_load_%s", n);
  buffer[BUFFER_DL - 1] = '\0';

  loader = dlsym(handle, buffer);

  error = dlerror();
  if (error) {
    idsa_chain_error_internal(c, "unable to resolve %s: %s", buffer, error);
    dlclose(handle);
    return NULL;
  }

  if (loader == NULL) {
    idsa_chain_error_internal(c, "%s resolves to NULL", buffer);
    dlclose(handle);
    return NULL;
  }

  result = (*loader) (c);
  if (result == NULL) {
    idsa_chain_error_internal(c, "unable to initialise module %s", n);
    dlclose(handle);
    return NULL;
  }

  /* check for inconsistencies if module interface should change in future
     if(result->m_version != IDSA_MODULE_INTERFACE_VERSION){
     }
   */

  result->m_handle = handle;

  return result;
#endif
}

static int idsa_module_prepare(IDSA_RULE_CHAIN * c, IDSA_MODULE * m)
{
  int complete;

  m->m_next = c->c_modules;
  c->c_modules = m;

#ifdef DEBUG
  fprintf(stderr, "idsa_module_prepare(): preparing module %s\n", m->m_name);
#endif

  /* FIXME: should check that we have a complete action and test set */
  complete = 0;

  if (m->test_start)
    complete++;
  if (m->test_cache)
    complete++;
  if (m->test_do)
    complete++;
  if (m->test_stop)
    complete++;

  if (complete % 4) {
    idsa_chain_error_internal(c, "module <%s> broken: tests only partially implemented", m->m_name);
  }

  if (m->action_start)
    complete++;
  if (m->action_cache)
    complete++;
  if (m->action_do)
    complete++;
  if (m->action_stop)
    complete++;

  if (complete % 4) {
    idsa_chain_error_internal(c, "module <%s> broken: actions only partially implemented", m->m_name);
  }

  if (complete == 0) {
    idsa_chain_error_internal(c, "module <%s> useless: neither tests nor actions implemented", m->m_name);
  }

  if (m->global_start)
    complete++;
  if (m->global_stop)
    complete++;

  if (complete % 2) {
    idsa_chain_error_internal(c, "module <%s> broken: incomplete global start/stop", m->m_name);
  }

  if (m->global_start) {
    m->m_state = (*m->global_start) (c);
  } else {
    m->m_state = NULL;
  }

  return c->c_error;
}
