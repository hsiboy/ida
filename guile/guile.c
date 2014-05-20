
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <idsa.h>
#include <idsa_internal.h>

#include <guile/gh.h>

#include "misc.h"

SCM idsa2scm(IDSA_UNIT * unit_handle)
{
  SCM result;

  char buffer[IDSA_M_MESSAGE];
  unsigned int buflen;

  unsigned int intval;
  unsigned int portval[2];

  unsigned int riskx;
  double riskval[2];

  result = SCM_UNDEFINED;

  switch (idsa_unit_type(unit_handle)) {
    /* WARNING: not all of these may be integers, needs to be fixed */
  case IDSA_T_INT:
  case IDSA_T_UID:
  case IDSA_T_GID:
  case IDSA_T_PID:
  case IDSA_T_TIME:
  case IDSA_T_ERRNO:
    if (idsa_unit_get(unit_handle, &intval, sizeof(int)) == sizeof(int)) {
      result = gh_int2scm(intval);
    }
    break;

  case IDSA_T_IPPORT:
    if (idsa_unit_get(unit_handle, portval, 2 * sizeof(int)) == (2 * sizeof(int))) {
      result = gh_ints2scm(portval, 2);
    }
    break;

  case IDSA_T_FLAG:
    if (idsa_unit_get(unit_handle, &intval, sizeof(int)) == sizeof(int)) {
      result = gh_bool2scm(intval);
    }
    break;

  case IDSA_T_RISK:
    if (idsa_unit_get(unit_handle, &riskx, sizeof(int)) == sizeof(int)) {
      riskval[0] = idsa_risk_severity(riskx);
      riskval[1] = idsa_risk_confidence(riskx);
      result = gh_doubles2scm(riskval, 2);
    }
    break;

  case IDSA_T_STRING:
  case IDSA_T_HOST:
  case IDSA_T_IP4ADDR:
  case IDSA_T_FILE:
  case IDSA_T_SADDR:
  default:
    buflen = idsa_unit_print(unit_handle, buffer, IDSA_M_MESSAGE, 0);
    if (buflen >= 0) {
      result = gh_str2scm(buffer, buflen);
    }
    break;
  }
  return result;
}

SCM build_list(IDSA_EVENT * event_handle)
{
  IDSA_UNIT *unit_handle;
  SCM list_head, list_new;
  SCM unit_name, unit_type, unit_value;
  unsigned int i;

  list_head = SCM_EOL;

  i = idsa_event_unitcount(event_handle);
  while (i) {
    i--;
    unit_handle = idsa_event_unitbynumber(event_handle, i);
    if (unit_handle) {

#ifdef TRACE
      fprintf(stderr, "build_list(): name=<%s>, type=<%d>\n", idsa_unit_name_get(unit_handle), idsa_type_name(idsa_unit_type(unit_handle)));
#endif

      unit_name = gh_str02scm(idsa_unit_name_get(unit_handle));
      unit_type = gh_str02scm(idsa_type_name(idsa_unit_type(unit_handle)));
      unit_value = idsa2scm(unit_handle);

      list_new = gh_list(unit_name, unit_type, unit_value, SCM_UNDEFINED);

      list_head = gh_cons(list_new, list_head);
    }
  }

  return list_head;
}

void local_main(int argc, char *argv[])
{
  SCM user_function, argument_list;
  IDSA_EVENT *event_handle;

  char read_buffer[IDSA_M_MESSAGE];
  int have_buffer, read_result, still_running, copy_bytes, still_more;

  char write_buffer[IDSA_M_MESSAGE];
  int should_write, have_written, write_result;

  gh_load(argv[1]);

  /* WTF ? why does gh_lookup("idsa") fail and this work ? */
  user_function = gh_eval_str("idsa");

#ifdef TRACE
  fprintf(stderr, "local_main(): user_function is %d\n", user_function);
#endif

  event_handle = idsa_event_new(0);
  if (event_handle == NULL) {
    exit(1);
  }
  still_more = 0;
  still_running = 1;
  have_buffer = 0;
  do {

    if (still_more == 0) {
      read_result = read(STDIN_FILENO, read_buffer + have_buffer, IDSA_M_MESSAGE - have_buffer);
#ifdef TRACE
      fprintf(stderr, "local_main(): read %d off stdin\n", read_result);
#endif
      switch (read_result) {
      case -1:
	switch (errno) {
	case EINTR:
	case EAGAIN:
	  break;
	default:
	  still_running = 0;
	  break;
	}
	break;
      case 0:
	still_running = 0;
	break;
      default:
	have_buffer += read_result;
	break;
      }
    }
#ifdef TRACE
    fprintf(stderr, "local_main(): buffer of <%d> bytes to frombuffer\n", have_buffer);
#endif

    still_more = 0;
    copy_bytes = idsa_event_frombuffer(event_handle, read_buffer, have_buffer);

#ifdef TRACE
    fprintf(stderr, "local_main(): read event in <%d> bytes\n", copy_bytes);
#endif

    if (copy_bytes > 0) {
      if (copy_bytes < have_buffer) {
	memmove(read_buffer, read_buffer + copy_bytes, have_buffer - copy_bytes);
	have_buffer -= copy_bytes;
	still_more = 1;
      } else {
	have_buffer = 0;
      }

      if (idsa_request_check(event_handle)) {
#ifdef TRACE
	fprintf(stderr, "local_main(): broken event\n");
#endif
	/* broken event -> major failure */
	still_running = 0;
      } else {
#ifdef TRACE
	fprintf(stderr, "local_main(): about to build argument list\n");
	idsa_event_dump(event_handle, stderr);
#endif
	argument_list = build_list(event_handle);

	idsa_reply_init(event_handle);

	if (gh_call1(user_function, argument_list) == SCM_BOOL_F) {
	  idsa_reply_deny(event_handle);
#ifdef TRACE
	  fprintf(stderr, "local_main(): false=deny\n");
#endif
	} else {
	  idsa_reply_allow(event_handle);
#ifdef TRACE
	  fprintf(stderr, "local_main(): true=allow\n");
#endif
	}

	should_write = idsa_event_tobuffer(event_handle, write_buffer, IDSA_M_MESSAGE);
	if (should_write > 0) {
	  have_written = 0;
	  do {
	    write_result = write(STDOUT_FILENO, write_buffer + have_written, should_write - have_written);
	    if (write_result < 0) {
	      switch (errno) {
	      case EAGAIN:
	      case EINTR:
		write_result = 0;
		break;
	      default:
		break;
	      }
	    } else {
	      have_written += write_result;
	    }
	  } while ((write_result >= 0) && (have_written < should_write));

	  if (have_written < should_write) {
	    still_running = 0;
	  }
	} else {
	  still_running = 0;
	}


      }

    } else {
      if (have_buffer == IDSA_M_MESSAGE) {
	/* buffer full, but no complete message -> error */
	still_running = 0;
      }
    }

  } while (still_running);


  exit(0);
}

int main(int argc, char **argv)
{
  int i, j;
  char *id = NULL;
  char *rootdir = NULL;
  char *local_argv[3];
  int allowfork = 1;

  local_argv[0] = argv[0];
  local_argv[1] = NULL;
  local_argv[2] = NULL;

  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	if (isatty(STDOUT_FILENO)) {
	  printf("(c) 2000 Marc Welz: Licensed under the terms of the GNU General Public License\n");
	  exit(0);
	} else {
	  fprintf(stderr, "%s: option -%c only available at command line\n", argv[0], argv[i][j]);
	  exit(1);
	}
	break;
      case 'h':
	if (isatty(STDOUT_FILENO)) {
	  printf("usage: %s [-f] [-i user] [-r chroot directory] guilescript.scm\n", argv[0]);
	  exit(0);
	} else {
	  fprintf(stderr, "%s: option -%c only available at command line\n", argv[0], argv[i][j]);
	  exit(1);
	}
      case 'i':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  id = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -i option requires a user id as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'r':
	j++;
	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  rootdir = argv[i] + j;
	  i++;
	  j = 1;
	} else {
	  fprintf(stderr, "%s: -r option requires a directory as parameter\n", argv[0]);
	  exit(1);
	}
	break;
      case 'f':
	allowfork = 0;
	j++;
	break;
      case '-':
	j++;
	break;
      case '\0':
	j = 1;
	i++;
	break;
      default:
	fprintf(stderr, "%s: unknown option -%c\n", argv[0], argv[i][j]);
	exit(1);
	break;
      }
    } else {			/* found script */
      local_argv[1] = argv[i];
      i++;
    }
  }

  if (local_argv[1] == NULL) {
    fprintf(stderr, "%s: nothing to run\n", argv[0]);
    exit(1);
  }

  if (allowfork == 0) {
    drop_fork(argv[0]);
  }

  /* WARNING: scm files have to be available in chrooted environment */
  drop_root(argv[0], id, rootdir);

#ifdef TRACE
  fprintf(stderr, "main(): entering local_main: %s %s\n", local_argv[0], local_argv[1]);
#endif

  /* WARNING: Lets hope the guile garbage collector is really clever */
  gh_enter(2, local_argv, local_main);

  return 0;
}
