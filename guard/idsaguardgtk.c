#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <idsa_internal.h>

#include <gtk/gtk.h>

#define COL_ALLOW    "forest green"
#define COL_DENY     "firebrick"
#define COL_NORMAL   "black"

#define TIMEOUT          4	/* seconds to wait in connect */
#define BUFFER (2*IDSA_M_MESSAGE+16)	/* space to read in stuff */
#define TOTAL  (IDSA_M_MESSAGE*10)	/* size at which we start pruning textbox */
#define FUZZ             5	/* fudge factor for scroll adjustment */

#define STATE_REQUEST    1	/* wait for an incomming event */
#define STATE_CLICK      2	/* wait for user to click accept or deny */
#define STATE_REPLY      3	/* wait for server to tell us answer */
#define STATE_INCOMPLETE 4	/* inside function, should never be visible */

typedef struct ig_data {
  char *ig_name;		/* name of socket */
  int ig_fd;			/* file descriptor */
  gint ig_tag;			/* file event tag */

  int ig_state;			/* state */
  int ig_map;			/* is window mapped ? */
  int ig_stay;			/* is mapping/unmapping disabled ? */

  GtkWidget *ig_window;
  GtkWidget *ig_text;
  GtkWidget *ig_toggle;
  guint ig_size;		/* characters in window */

  GtkAdjustment *ig_adj;

  GdkColor ig_deny;
  GdkColor ig_allow;
  GdkColor ig_normal;

  IDSA_EVENT *ig_event;

  unsigned int ig_count;

  int ig_have;			/* how much is in the buffer */

  char ig_buffer[BUFFER];

  IDSA_PRINT_HANDLE *ig_handle;
  int ig_print;
  char ig_output[BUFFER];
} IG_DATA;

#ifndef VERSION
#define VERSION "unknown"
#endif

volatile int timeout = 0;

/****************************************************************************/

void ig_message(IG_DATA * ig, char *fmt, ...);
void ig_read(gpointer data, gint source, GdkInputCondition condition);
void ig_disconnect(IG_DATA * ig);
int ig_connect(IG_DATA * ig);
int ig_reset(IG_DATA * ig);

int ig_reply(IG_DATA * ig);
int ig_request(IG_DATA * ig);

/****************************************************************************/

void ig_alarm(int s)
{
  timeout = 1;
}

void ig_wake(IG_DATA * ig)
{
  /* possibly ring a bell here too */

  if (ig->ig_stay) {
    return;
  }

  if (ig->ig_map) {
    return;
  }
#ifdef TRACE
  g_print("ig_wake(): mapping\n");
#endif

  ig->ig_map = 1;
  gtk_widget_map(ig->ig_window);
}

void ig_snooze(IG_DATA * ig)
{
  if (ig->ig_fd <= 0) {
    ig_message(ig, "Not connected\n");
    return;
  }

  if (ig->ig_stay) {
    return;
  }

  if (!ig->ig_map) {
    return;
  }
#ifdef TRACE
  g_print("ig_snooze(): unmapping\n");
#endif
  ig->ig_map = 0;
  gtk_widget_unmap(ig->ig_window);
}

void ig_message(IG_DATA * ig, char *fmt, ...)
{
  char buffer[BUFFER];

  va_list args;

  va_start(args, fmt);

  vsnprintf(buffer, BUFFER - 1, fmt, args);
  buffer[BUFFER - 1] = '\0';

  fputs(buffer, stderr);

  if (ig) {
    gtk_text_insert(GTK_TEXT(ig->ig_text), NULL, &(ig->ig_normal), NULL, buffer, -1);
    ig->ig_size = gtk_text_get_length(GTK_TEXT(ig->ig_text));
    ig->ig_print = 0;
  }

  va_end(args);
}

void ig_disconnect(IG_DATA * ig)
{
  if (ig->ig_fd >= 0) {
    gdk_input_remove(ig->ig_tag);

    ig_message(ig, "Disconnected from %s\n", ig->ig_name);

    close(ig->ig_fd);
    ig->ig_fd = (-1);

    ig->ig_size = gtk_text_get_length(GTK_TEXT(ig->ig_text));
  }
}

int ig_connect(IG_DATA * ig)
{
  struct sockaddr_un sa;
  struct sigaction scurrent, srestore;
  int connect_result;

  ig->ig_state = STATE_REQUEST;

  ig->ig_count = 0;
  ig->ig_have = 0;

  if (ig->ig_name == NULL) {
    ig_message(ig, "Please specify a unix socket on the commandline\n");
    return 1;
  }

  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, ig->ig_name, sizeof(sa.sun_path));

  ig->ig_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ig->ig_fd < 0) {
    ig_message(ig, "Unable to create socket: %s\n", strerror(errno));

    ig->ig_fd = (-1);
    return 1;
  }

  ig_message(ig, "Connecting to %s ... ", ig->ig_name);

  sigfillset(&(scurrent.sa_mask));
  scurrent.sa_flags = 0;
  scurrent.sa_handler = ig_alarm;

  sigaction(SIGALRM, &scurrent, &srestore);
  alarm(TIMEOUT);
  connect_result = connect(ig->ig_fd, (struct sockaddr *) &sa, sizeof(sa));
  alarm(0);
  sigaction(SIGALRM, &srestore, NULL);

  if (connect_result != 0) {
    ig_message(ig, "failed : %s\n", timeout ? "connection attempt timed out - stale connection or other instance running" : strerror(errno));
    close(ig->ig_fd);
    ig->ig_fd = (-1);
    return 1;
  }

  gtk_window_set_title(GTK_WINDOW(ig->ig_window), ig->ig_name);

  ig_message(ig, "ok\n");

  ig->ig_size = gtk_text_get_length(GTK_TEXT(ig->ig_text));
  ig->ig_tag = gdk_input_add(ig->ig_fd, GDK_INPUT_READ, ig_read, ig);

  return 0;
}

gint ig_reset(IG_DATA * ig)
{
  ig_disconnect(ig);
  return ig_connect(ig);
}

int ig_more(IG_DATA * ig)
{
  fd_set fsr;
  struct timeval tv;

  FD_ZERO(&fsr);
  FD_SET(ig->ig_fd, &fsr);

  tv.tv_sec = 0;
  tv.tv_usec = 1;

  if (select(ig->ig_fd + 1, &fsr, NULL, NULL, &tv) <= 0) {
    return 0;
  }

  return 1;
}

int ig_request(IG_DATA * ig)
{
  int result;

  ig_wake(ig);

  result = idsa_event_frombuffer(ig->ig_event, ig->ig_buffer, ig->ig_have);

#ifdef TRACE
  g_print("ig_request(): before: result=%d, have=%d, size=%u, count=%u\n", result, ig->ig_have, ig->ig_size, ig->ig_count);
#endif

  if (result <= 0) {

    /* if there is still stuff to read try again */
    if ((ig->ig_have < IDSA_M_MESSAGE) && ig_more(ig)) {
      return 0;
    }

    ig_message(ig, "Received malformed event from %s\n", ig->ig_name);
#ifdef TRACE
    ig->ig_buffer[ig->ig_have] = '\0';
    g_print("ig_request(): %s\n", ig->ig_buffer);
#endif
    ig_reset(ig);
    return -1;			/* bomb: mangled event */
  }
  ig->ig_count++;

  /* copy read stuff into output buffer */
  if (ig->ig_handle) {
    ig->ig_print = idsa_print_do(ig->ig_event, ig->ig_handle, ig->ig_output, BUFFER);
  } else {
    memcpy(ig->ig_output, ig->ig_buffer, result);
    ig->ig_print = result;
  }

  /* make space in input buffer */
  if (result < ig->ig_have) {
    memmove(ig->ig_buffer, ig->ig_buffer + result, ig->ig_have - result);
    ig->ig_have = ig->ig_have - result;
  } else {
    ig->ig_have = 0;
  }

  gtk_text_freeze(GTK_TEXT(ig->ig_text));
  /* make space in text widget if necessary */
  if (ig->ig_print + ig->ig_size > TOTAL) {
    gtk_text_set_point(GTK_TEXT(ig->ig_text), 0);
    gtk_text_forward_delete(GTK_TEXT(ig->ig_text), (ig->ig_print + ig->ig_size) - TOTAL);
    ig->ig_size = gtk_text_get_length(GTK_TEXT(ig->ig_text));
    gtk_text_set_point(GTK_TEXT(ig->ig_text), ig->ig_size);
  }
  gtk_text_insert(GTK_TEXT(ig->ig_text), NULL, &(ig->ig_normal), NULL, ig->ig_output, ig->ig_print);
  ig->ig_size = ig->ig_size + ig->ig_print;

  gtk_text_thaw(GTK_TEXT(ig->ig_text));

#ifdef TRACE
  g_print("ig_request(): after: print=%d, have=%d, size=%u, count=%u\n", ig->ig_print, ig->ig_have, ig->ig_size, ig->ig_count);
  /* g_print("inserted, mine=%d, internal=%d, adj=%f<%f<%f+%f\n", ig->ig_size, gtk_text_get_length(GTK_TEXT(ig->ig_text)),ig->ig_adj->lower,ig->ig_adj->value,ig->ig_adj->upper,ig->ig_adj->page_size); */
#endif

  ig->ig_state = STATE_CLICK;

  /* still stuff to be processed */
  if (ig->ig_have > 0) {
    ig_reply(ig);
  }

  return 0;
}

#define SMALL           32	/* small input buffer to get user commands */

int ig_reply(IG_DATA * ig)
{
  int allow;
  unsigned result;
  char local[SMALL];

  ig->ig_buffer[ig->ig_have] = '\0';	/* safe, we only read in BUFFER-1 */
  switch (ig->ig_buffer[0]) {
  case 'A':
    allow = 1;
    break;
  case 'D':
    allow = 0;
    break;
  default:
#ifdef TRACE
    g_print("ig_reply(): failure: [0]=%c\n", ig->ig_buffer[0]);
#endif
    break;
  }

  result = snprintf(local, SMALL, "%c%u\n", ig->ig_buffer[0], ig->ig_count);

  /* if there is still stuff to read try again */
  if ((result > ig->ig_have) && ig_more(ig)) {
    return 0;
  }

  allow = (ig->ig_buffer[0] == 'A') ? 1 : 0;

  if (strncmp(local, ig->ig_buffer, result)) {
    ig_message(ig, "Event count mismatch\n");
    ig_reset(ig);
    return -1;			/* bomb: desynchronized */
  }
#ifdef TRACE
  g_print("ig_reply(): before: reply <%c...>, have=%d\n", ig->ig_buffer[0], ig->ig_have);
#endif

  gtk_text_freeze(GTK_TEXT(ig->ig_text));
  gtk_text_backward_delete(GTK_TEXT(ig->ig_text), ig->ig_print);
  gtk_text_insert(GTK_TEXT(ig->ig_text), NULL, allow ? &(ig->ig_allow) : &(ig->ig_deny), NULL, ig->ig_output, ig->ig_print);
  gtk_text_thaw(GTK_TEXT(ig->ig_text));

  ig->ig_print = 0;

  if (result < ig->ig_have) {
    memmove(ig->ig_buffer, ig->ig_buffer + result, ig->ig_have - result);
    ig->ig_have = ig->ig_have - result;
  } else {
    ig->ig_have = 0;
  }

#ifdef TRACE
  g_print("ig_reply(): after: have=%d buffer[0]=%c\n", ig->ig_have, ig->ig_buffer[0]);
#endif

  ig_snooze(ig);

  ig->ig_state = STATE_REQUEST;

  if (ig->ig_have > 0) {
    ig_request(ig);
  }

  return 0;
}

void ig_read(gpointer data, gint source, GdkInputCondition condition)
{
  IG_DATA *ig;
  int read_result;

  ig = data;

  read_result = read(ig->ig_fd, ig->ig_buffer + ig->ig_have, (BUFFER - 1) - ig->ig_have);
  if (read_result <= 0) {
    if (read_result < 0) {
      ig_message(ig, "Read from %s failed: %s\n", ig->ig_name, strerror(errno));
    } else {
      ig_message(ig, "Remote side closed %s\n", ig->ig_name);
    }
    ig_reset(ig);
    return;			/* bomb: read failed */
  }
#ifdef TRACE
  g_print("ig_read(): have=%d+%d\n", ig->ig_have, read_result);
#endif
  ig->ig_have += read_result;
#ifdef TRACE
  ig->ig_buffer[ig->ig_have] = '\0';
  g_print("ig_read(): content=%s\n", ig->ig_buffer);
#endif

  switch (ig->ig_state) {
  case STATE_REQUEST:
    ig_request(ig);
    break;

  case STATE_CLICK:
  case STATE_REPLY:
    ig_reply(ig);
    break;

  default:
    ig_message(ig, "Critical failure, unknown state\n");
    ig_reset(ig);
    break;
  }

  if (ig->ig_adj->value + ig->ig_adj->page_size + FUZZ < ig->ig_adj->upper) {
    gtk_adjustment_set_value(ig->ig_adj, ig->ig_adj->upper - (ig->ig_adj->page_size + FUZZ));
  }
}

void ig_decide(IG_DATA * ig, int allow)
{
  int should_write;
  char buffer[BUFFER];

#ifdef TRACE
  g_print("ig_decide(): count=%u, state=%d, %s\n", ig->ig_count, ig->ig_state, allow ? "allow" : "deny");
#endif

  if (ig->ig_fd <= 0) {
    ig_connect(ig);
    return;
  }

  if (ig->ig_state != STATE_CLICK) {
    return;			/* bomb: not ready */
  }

  should_write = snprintf(buffer, BUFFER - 1, "%c%u\n", (allow ? 'A' : 'D'), ig->ig_count);
  if (should_write != write(ig->ig_fd, buffer, should_write)) {
    ig_message(ig, "Write to %s failed: %s\n", ig->ig_name, strerror(errno));
    ig_reset(ig);
    return;			/* bomb: answer failed */
  }

  ig->ig_state = STATE_REPLY;
}

void ig_allow(GtkWidget * widget, gpointer data)
{
  ig_decide(data, 1);
}

void ig_deny(GtkWidget * widget, gpointer data)
{
  ig_decide(data, 0);
}

void ig_stay(GtkWidget * widget, gpointer data)
{
  IG_DATA *ig;
  ig = data;

#ifdef TRACE
  g_print("stay toggle\n");
#endif

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ig->ig_toggle))) {
    ig->ig_stay = 1;
  } else {
    ig->ig_stay = 0;
    if (ig->ig_state == STATE_REQUEST) {
      ig_snooze(ig);
    }
  }
}

void ig_destroy(GtkWidget * widget, gpointer data)
{
  IG_DATA *ig;

#ifdef TRACE
  g_print("destroy\n");
#endif
  ig = data;

  ig_disconnect(ig);
  idsa_event_free(ig->ig_event);

  gtk_main_quit();
}

void ig_hide(IG_DATA * ig)
{
  if (ig) {
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ig->ig_toggle), FALSE);
  }
}

void ig_setup(IG_DATA * ig)
{
  GtkWidget *window;
  GtkWidget *exit;
  GtkWidget *allow;
  GtkWidget *deny;
  GtkWidget *text;
  GtkWidget *stay;

  GtkWidget *vbox;
  GtkWidget *hbox;

  GtkAdjustment *adj;

  GdkColormap *map;

  ig->ig_fd = (-1);
  ig->ig_name = NULL;
  ig->ig_size = 0;

  ig->ig_count = 0;
  ig->ig_have = 0;

  ig->ig_handle = NULL;
  ig->ig_print = 0;

  ig->ig_state = STATE_REQUEST;
  ig->ig_map = 1;
  ig->ig_stay = 1;

#ifdef TRACE
  memset(ig->ig_buffer, '\0', BUFFER);
#endif

  ig->ig_event = idsa_event_new(0);

  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(window), "idsaguard");
  gtk_window_set_default_size(GTK_WINDOW(window), 600, 210);

  gtk_signal_connect(GTK_OBJECT(window), "delete_event", GTK_SIGNAL_FUNC(gtk_false), ig);
  gtk_signal_connect(GTK_OBJECT(window), "destroy", GTK_SIGNAL_FUNC(ig_destroy), ig);

  exit = gtk_button_new_with_label("exit");
  gtk_signal_connect(GTK_OBJECT(exit), "clicked", GTK_SIGNAL_FUNC(ig_destroy), ig);

  stay = gtk_toggle_button_new_with_label("stay");
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(stay), TRUE);
  gtk_signal_connect(GTK_OBJECT(stay), "toggled", GTK_SIGNAL_FUNC(ig_stay), ig);

  allow = gtk_button_new_with_label("allow");
  gtk_signal_connect(GTK_OBJECT(allow), "clicked", GTK_SIGNAL_FUNC(ig_allow), ig);
  deny = gtk_button_new_with_label("deny");
  gtk_signal_connect(GTK_OBJECT(deny), "clicked", GTK_SIGNAL_FUNC(ig_deny), ig);

  hbox = gtk_hbox_new(FALSE, 1);
  gtk_box_pack_start(GTK_BOX(hbox), allow, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(hbox), deny, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(hbox), stay, FALSE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(hbox), exit, FALSE, TRUE, 0);

  adj = GTK_ADJUSTMENT(gtk_adjustment_new(0.0, 0.0, 1.0, 0.01, 0.1, 1.0));

  text = gtk_text_new(NULL, adj);
  gtk_text_set_editable(GTK_TEXT(text), FALSE);
  gtk_text_set_word_wrap(GTK_TEXT(text), FALSE);
  gtk_text_set_line_wrap(GTK_TEXT(text), TRUE);

  vbox = gtk_vbox_new(FALSE, 1);
  gtk_box_pack_start(GTK_BOX(vbox), text, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, TRUE, 0);

  gtk_container_add(GTK_CONTAINER(window), vbox);

  ig->ig_window = window;
  ig->ig_text = text;
  ig->ig_toggle = stay;
  ig->ig_adj = adj;

  map = gdk_colormap_get_system();

  gdk_color_parse(COL_DENY, &(ig->ig_deny));
  gdk_color_parse(COL_ALLOW, &(ig->ig_allow));
  gdk_color_parse(COL_NORMAL, &(ig->ig_normal));

  gdk_colormap_alloc_color(map, &(ig->ig_deny), FALSE, TRUE);
  gdk_colormap_alloc_color(map, &(ig->ig_allow), FALSE, TRUE);
  gdk_colormap_alloc_color(map, &(ig->ig_normal), FALSE, TRUE);

  gtk_widget_show_all(window);

  ig_message(ig, "Idsaguard version %s\n", VERSION);

}

void ig_name(IG_DATA * ig, char *name)
{
  if (ig) {
    if (ig->ig_name) {
      ig_message(ig, "Warning: ignoring %s\n", ig->ig_name);
    }
    ig->ig_name = name;
  }
}

void ig_usage(IG_DATA * ig, char *name)
{
  ig_message(ig, "Usage: %s [-u] -[-f format] [-F custom format] /path/to/unix/socket\n", name);
  ig_message(ig, "-u     unmap window at startup\n");
  ig_message(ig, "-f     use an alternate output format, eg: syslog, ulm, xml\n");
  ig_message(ig, "-F     specify a custom output format, eg: \"%{time} %{name} \"\n");
}

int main(int argc, char **argv)
{
  IG_DATA data, *ig;
  struct rlimit r;
  int i, j;
  int result;
  int unmap;
  char format;

  signal(SIGPIPE, SIG_IGN);
  result = 0;
  unmap = 0;

  if (gtk_init_check(&argc, &argv)) {
    ig = &data;
    ig_setup(ig);
  } else {
    result = 1;
    ig = NULL;
  }

  /* WARNING: ig_name and ig_message are the only functions safe to call for ig==NULL */

  i = 1;
  j = 1;
  while (i < argc) {
    if (argv[i][0] == '-') {
      switch (argv[i][j]) {
      case 'c':
	ig_message(ig, "(c) 2002 Marc Welz: Licensed under the GNU GPL\n");
	if (!strcmp(argv[i] + j, "copyright")) {
	  i++;
	  j = 0;
	}
	result = 0;
	break;
      case 'h':
	ig_usage(ig, argv[0]);
	if (!strcmp(argv[i] + j, "help")) {
	  i++;
	  j = 0;
	}
	result = 0;
	break;
      case 'u':
	unmap = 1;
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
	  if (ig) {
	    ig->ig_handle = (format == 'f') ? idsa_print_format(argv[i] + j) : idsa_print_parse(argv[i] + j);
	    if (ig->ig_handle == NULL) {
	      ig_message(ig, "Unable to process output format %s\n", argv[i] + j);
	    }
	  }
	  i++;
	  j = 0;
	} else {
	  ig_message(ig, "-%c option requires an output format as parameter\n", format);
	}
	break;
      case '-':
	break;
      case '\0':
	j = 0;
	i++;
	break;
      default:
	ig_message(ig, "Unknown option -%c\n", argv[i][j]);
	result = 1;
	break;
      }
      j++;
    } else {
      ig_name(ig, argv[i]);
      i++;
    }
  }

  r.rlim_cur = 0;
  r.rlim_max = 0;
  if (setrlimit(RLIMIT_NPROC, &r)) {
    ig_message(ig, "Unable to activate resource limits: %s\n", strerror(errno));
  }

  if (ig) {
    ig_connect(ig);
    if (unmap) {
      ig_hide(ig);
    }
    gtk_main();
  } else {
    if (result) {
      ig_message(ig, "Unable to initialize GTK interface\n");
      if (getenv("DISPLAY") == NULL) {
	ig_message(ig, "Suggest using idsaguardtty if X unavailable\n");
      }
    }
  }

  return result;
}
