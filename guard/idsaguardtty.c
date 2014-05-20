/* link against idsa and ncurses */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sysexits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/time.h>

#ifdef STANDOUT
#include <ncurses.h>
#include <term.h>
#endif

#include <idsa_internal.h>

#define TIMEOUT          4	/* seconds to wait in connect */
#define BUFFER (2*IDSA_M_MESSAGE+16)	/* space to read in stuff */
#define SMALL           32	/* small input buffer to get user commands */

#define STATE_QUIT       0	/* about to exit */
#define STATE_REQUEST    1	/* wait for an incomming event */
#define STATE_CLICK      2	/* wait for user to answer with accept or deny */
#define STATE_REPLY      3	/* wait for server to tell us answer */

int output(IDSA_EVENT * event, IDSA_PRINT_HANDLE * handle)
{
  char buffer[BUFFER];
  int result;

  result = idsa_print_do(event, handle, buffer, BUFFER - 1);
  if (result <= 0) {
    printf("no output\n");
  } else {
    buffer[result] = '\0';
    puts(buffer);
  }
  fflush(stdout);

  return 0;
}

void fail(int s)
{
}

void usage(char *name)
{
  printf("Usage: %s [-b] [-f format] [-F custom format] /path/to/unix/socket\n", name);
  printf("-b     ring bell\n");
  printf("-f     use an alternate output format, eg: syslog, ulm, xml\n");
  printf("-F     specify a custom output format\n");
}

void help(char *name)
{
  printf("Keys:\n" " a  allow\n" " d  deny\n" " s  silent\n" " b  bell\n" " q  quit\n");
}

int main(int argc, char **argv)
{
  int i, j;
  char *name;
  struct sockaddr_un sa;
  struct sigaction scurrent, srestore;
  int fd, run, ring, result, answer, have, flags;
  unsigned int count;
  struct termios termattr, termrestore;
  char input, format;
  fd_set fsr;
  char remote[BUFFER], local[SMALL];
  IDSA_EVENT *event;
  IDSA_PRINT_HANDLE *handle;
  char *bright, *normal;

  ring = 0;
  name = NULL;
  handle = NULL;

  answer = 0;
  result = EX_OK;

  i = j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	printf("(c) 2002 Marc Welz: Licensed under the GNU GPL\n");
	return EX_OK;
      case 'h':
	usage(argv[0]);
	return EX_OK;
      case 'b':
	ring = 1;
	break;
      case 'F':
      case 'f':
	format = argv[i][j];
	j++;

	if (argv[i][j] == '\0') {
	  j = 0;
	  i++;
	}
	if (i < argc) {
	  handle = (format == 'f') ? idsa_print_format(argv[i] + j) : idsa_print_parse(argv[i] + j);
	  if (handle == NULL) {
	    fprintf(stderr, "%s: unable to process output format %s\n", argv[0], argv[i] + j);
	    return EX_SOFTWARE;
	  }
	  i++;
	  j = 0;
	} else {
	  fprintf(stderr, "%s: -%c option requires an output format as parameter\n", argv[0], format);
	  return EX_USAGE;
	}
	break;
      case '-':
	break;
      case '\0':
	j = 0;
	i++;
	break;
      default:
	fprintf(stderr, "%s: Unknown option -%c\n", argv[0], argv[i][j]);
	return EX_USAGE;
	break;
      }
      j++;
    } else {
      name = argv[i];
      i++;
    }
  }

  if (name == NULL) {
    fprintf(stderr, "%s: Need a unix domain socket\n", argv[0]);
    return EX_USAGE;
  }

  if (handle == NULL) {
    handle = idsa_print_format("internal");
    if (handle == NULL) {
      fprintf(stderr, "%s: Internal failure, unable to process default print format\n", argv[0]);
      return EX_SOFTWARE;
    }
  }

  if (!isatty(STDIN_FILENO)) {
    fprintf(stderr, "%s: My standard input needs to be an interactive terminal\n", argv[0]);
    return EX_USAGE;
  }

  event = idsa_event_new(0);
  if (event == NULL) {
    fprintf(stderr, "%s: Unable to allocate data for an event\n", argv[0]);
    return EX_SOFTWARE;
  }

  bright = NULL;
  normal = NULL;
#ifdef STANDOUT
  if (setupterm(NULL, STDOUT_FILENO, &result) == OK) {
    bright = tigetstr("smso");
    normal = tigetstr("rmso");
  }
#endif

  signal(SIGPIPE, SIG_IGN);

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, name, sizeof(sa.sun_path));

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "%s: Unable to create socket: %s\n", argv[0], strerror(errno));
    return EX_OSERR;
  }

  printf("Connecting to %s ... ", name);
  fflush(stdout);

  sigfillset(&(scurrent.sa_mask));
  scurrent.sa_flags = 0;
  scurrent.sa_handler = fail;

  sigaction(SIGALRM, &scurrent, &srestore);
  alarm(TIMEOUT);

  if (connect(fd, (struct sockaddr *) &sa, sizeof(sa))) {
    printf("failed\n");
    fprintf(stderr, "%s: Connect failed: %s\n", argv[0], strerror(errno));
    return EX_OSERR;
  }

  printf("ok\n");

  flags = fcntl(fd, F_GETFL, 0);
  if ((flags == (-1)) || (fcntl(fd, F_SETFL, O_NONBLOCK | flags) == (-1))) {
    fprintf(stderr, "%s: Unable to make socket %s nonblocking: %s\n", argv[0], name, strerror(errno));
    return EX_OSERR;
  }

  alarm(0);
  sigaction(SIGALRM, &srestore, NULL);

  count = 1;

  fflush(stdout);
  fflush(stderr);

  if (tcgetattr(STDIN_FILENO, &termrestore) || tcgetattr(STDIN_FILENO, &termattr)) {
    fprintf(stderr, "%s: Unable to get terminal information: %s\n", argv[0], strerror(errno));
    return EX_OSERR;
  }

  termattr.c_lflag &= ~(ICANON | ECHO);
  termattr.c_cc[VMIN] = 0;
  termattr.c_cc[VTIME] = 0;

  if (tcsetattr(STDIN_FILENO, TCSANOW, &termattr)) {
    fprintf(stderr, "%s: Unable to change terminal properties: %s\n", argv[0], strerror(errno));
    return EX_OSERR;
  }

  printf("%s version %s: Press ? for help\n", argv[0], VERSION);

  run = STATE_REQUEST;
  while (run != STATE_QUIT) {
    FD_ZERO(&fsr);
    FD_SET(fd, &fsr);
    FD_SET(STDIN_FILENO, &fsr);

    if (select(fd + 1, &fsr, NULL, NULL, NULL) <= 0) {
      fprintf(stderr, "%s: Select failed: %s\n", argv[0], strerror(errno));
      run = STATE_QUIT;
      result = EX_OSERR;
    }

    if (FD_ISSET(fd, &fsr)) {
#ifdef TRACE
      fprintf(stderr, "main(): socket active\n");
#endif
      have = 0;
      do {
	result = read(fd, remote + have, BUFFER - have);

	if (result <= 0) {
	  if (result == 0) {
	    fprintf(stderr, "%s: Remote side on socket %s closed connection\n", argv[0], name);
	    run = STATE_QUIT;
	    result = EX_SOFTWARE;
	  } else {
	    switch (errno) {
	    case EAGAIN:
	    case EINTR:
	      result = have;
	      break;
	    default:
	      fprintf(stderr, "%s: Read from socket %s failed: %s\n", argv[0], name, strerror(errno));
	      run = STATE_QUIT;
	      result = EX_OSERR;
	      break;
	    }
	  }
	} else {
	  have += result;
	}

	if (result > 0) {
	  switch (run) {
	  case STATE_REQUEST:
#ifdef TRACE
	    fprintf(stderr, "main(): converted %d to buffer with size %d\n", result, have);
#endif
	    result = idsa_event_frombuffer(event, remote, have);
	    if (result <= 0) {
	      fprintf(stderr, "%s: Read malformed event from socket %s\n", argv[0], name);
	      run = STATE_QUIT;
	      result = EX_SOFTWARE;
	    } else {

	      /* FIXME: could be a fancy print */
	      output(event, handle);

	      if (result < have) {
		memmove(remote, remote + result, have - result);
		have -= result;
	      } else {
		have = 0;
	      }
	      run = STATE_CLICK;
	    }

	    /* FIXME: what about lots of events in single read ? */

	    break;
	  case STATE_CLICK:
	  case STATE_REPLY:
	    switch (remote[0]) {
	    case 'A':
	    case 'D':
	      result = snprintf(local, SMALL, "%c%u\n", remote[0], count);
#ifdef TRACE
	      fprintf(stderr, "main(): comparing %d bytes of %s against buffer of %d %32s\n", result, local, have, remote);
#endif
	      if (strncmp(local, remote, result)) {
		fprintf(stderr, "%s: Received malformed answer from socket %s\n", argv[0], name);
		run = STATE_QUIT;
		result = EX_SOFTWARE;
	      } else {

#ifdef STANDOUT
		if (bright)
		  putp(bright);
#endif
		puts((remote[0] == 'A') ? "allowed" : "denied");
#ifdef STANDOUT
		if (normal)
		  putp(normal);
#endif

		if (result < have) {
		  memmove(remote, remote + result, have - result);
		  have -= result;
		} else {
		  have = 0;
		}
		count++;
		run = STATE_REQUEST;
	      }
	      break;
	    default:
	      fprintf(stderr, "%s: Read malformed answer from socket %s\n", argv[0], name);
	      run = STATE_QUIT;
	      result = EX_SOFTWARE;
	      break;
	    }
	    break;
	  }
	}
      } while ((result > 0) && (run != STATE_QUIT));

      if (ring && (run == STATE_CLICK)) {
	putchar('\a');
	fflush(stdout);
      }
    }

    input = 0;
    if (FD_ISSET(STDIN_FILENO, &fsr)) {
#ifdef TRACE
      fprintf(stderr, "main(): terminal active\n");
#endif
      do {
	result = read(STDIN_FILENO, local, SMALL);
	switch (result) {
	case -1:
	  switch (errno) {
	  case EAGAIN:
	  case EINTR:
	    break;
	  default:
	    fprintf(stderr, "%s: Read from terminal failed: %s\n", argv[0], strerror(errno));
	    run = STATE_QUIT;
	    result = EX_OSERR;
	    break;
	  }
	  break;
	case 0:
	  break;
	default:
	  input = local[result - 1];
	  break;
	}
      } while ((result > 0) && (run != STATE_QUIT));
    }
#ifdef TRACE
    fprintf(stderr, "main(): input is 0x%02x, state=%d\n", input, run);
#endif

    switch (input) {
    case 'q':
    case 'x':
      run = STATE_QUIT;
      result = EX_OK;
      input = 0;
      break;
    case 'h':
    case '?':
      help(argv[0]);
      input = 0;
      break;
    case 'a':
    case 'A':
      answer = 1;
      break;
    case 'd':
    case 'D':
      answer = 0;
      break;
    case 's':
      ring = 0;
      printf("bell disabled\n");
      break;
    case 'b':
      ring = 1;
      printf("bell activated\a\n");
      break;
    }

    if ((input > 0) && (run == STATE_CLICK)) {
      result = snprintf(local, SMALL - 1, "%c%u\n", (answer ? 'A' : 'D'), count);
#ifdef TRACE
      fprintf(stderr, "main(): writing: %s", local);
#endif
      if (result != write(fd, local, result)) {
	fprintf(stderr, "%s: write to socket %s failed: %s\n", argv[0], name, strerror(errno));
	run = STATE_QUIT;
	result = EX_OSERR;
      } else {
	run = STATE_REPLY;
      }
    }

  }

  if (tcsetattr(STDIN_FILENO, TCSANOW, &termrestore)) {
    fprintf(stderr, "%s: Unable to restore terminal properties: %s\n", argv[0], strerror(errno));
    return EX_OSERR;
  }

  return result;
}
