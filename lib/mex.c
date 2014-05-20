#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <idsa_internal.h>

#define MEX_BUFFER        4096

#define MEX_ERROR_OK      0x00	/* no error */
#define MEX_ERROR_TOOLONG 0x01	/* token too long */
#define MEX_ERROR_READ    0x02	/* read failure */
#define MEX_ERROR_MEMORY  0x03	/* malloc failure */
#define MEX_ERROR_LEX     0x04	/* lexer failure */
#define MEX_MAX_ERROR     0x05	/* size of error table */

#define MEX_STATE_QUIT    0x00
#define MEX_STATE_EATWS   0x01
#define MEX_STATE_EATHASH 0x02
#define MEX_STATE_WORD    0x03
#define MEX_STATE_STRING  0x04

static void idsa_mex_collect(IDSA_MEX_STATE * m);
static IDSA_MEX_TOKEN *idsa_mex_new(int id, int type, char *buf, int len, int line);
static IDSA_MEX_TOKEN *idsa_mex_token(IDSA_MEX_STATE * m);
static int idsa_mex_lookup(IDSA_MEX_STATE * m, unsigned char *s);
static void idsa_mex_free(IDSA_MEX_TOKEN * t);

IDSA_MEX_STATE *idsa_mex_file(char *fname)
{
  IDSA_MEX_STATE *m = NULL;
  int fd;

#ifdef DEBUG
  fprintf(stderr, "mex_file(): opening <%s>\n", fname);
#endif

  fd = open(fname, O_RDONLY);
  if (fd != (-1)) {
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    m = idsa_mex_fd(fd);
  }
  return m;
}

IDSA_MEX_STATE *idsa_mex_fd(int fd)
{
  IDSA_MEX_STATE *m;
  struct stat st;
  char *ptr;
  caddr_t addr;
  unsigned int i;

  m = NULL;
  if (fstat(fd, &st) == 0) {
    addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr != MAP_FAILED) {
      ptr = addr;
#ifdef DEBUG
      fprintf(stderr, "mex_fd(): got mapped file at %p\n", ptr);
#endif
      m = malloc(sizeof(IDSA_MEX_STATE));
      if (m) {
	m->m_read = st.st_size;
	m->m_buf = ptr;

	m->m_unmap = 1;

	m->m_head = NULL;
	m->m_this = NULL;
	m->m_lexed = 0;
	m->m_line = 1;

	m->m_error = MEX_ERROR_OK;

	m->m_keywords = NULL;
	for (i = 0; i < 256; i++) {
	  m->m_keychars[i] = 0;
	}
      } else {
	munmap(ptr, st.st_size);
      }
    } else {
#ifdef DEBUG
      fprintf(stderr, "mex_fd(): unable to map file\n");
#endif
    }
  }

  close(fd);

  return m;
}

IDSA_MEX_STATE *idsa_mex_buffer(char *buffer, int length)
{
  IDSA_MEX_STATE *m;
  unsigned int i;

  m = NULL;
  if (length > 0) {
    m = malloc(sizeof(IDSA_MEX_STATE));
    if (m) {
      m->m_read = length;
      m->m_buf = buffer;

      m->m_head = NULL;
      m->m_this = NULL;
      m->m_lexed = 0;
      m->m_line = 1;

      m->m_error = MEX_ERROR_OK;
      m->m_unmap = 0;

      m->m_keywords = NULL;
      for (i = 0; i < 256; i++) {
	m->m_keychars[i] = 0;
      }
    }
  }

  return m;
}

int idsa_mex_close(IDSA_MEX_STATE * m)
{
  int result;
  IDSA_MEX_TOKEN *t, *u;

  result = m->m_error;

  /* zap all tokens */
  t = m->m_head;
  while (t) {
    u = t;
    t = t->t_next;
    idsa_mex_free(u);
  }
  m->m_head = NULL;
  m->m_this = NULL;

  if (m->m_unmap) {
    munmap(m->m_buf, m->m_read);
    m->m_unmap = 0;
  }
  m->m_buf = NULL;

  free(m);

  return result;
}

int idsa_mex_tables(IDSA_MEX_STATE * m, IDSA_MEX_KEYCHAR * kc, IDSA_MEX_KEYWORD * kw)
{
  unsigned int i;

  for (i = 0; i < 256; i++) {
    m->m_keychars[i] = 0;
  }

  for (i = 0; kc[i].k_name != '\0'; i++) {
    m->m_keychars[(int) (kc[i].k_name)] = kc[i].k_id;
  }

  m->m_keywords = kw;

  return 0;
}

static char *idsa_mex_error_table[MEX_MAX_ERROR] = {
  [MEX_ERROR_OK] = NULL,
  [MEX_ERROR_TOOLONG] = "oversized token",
  [MEX_ERROR_READ] = "failure to read input",
  [MEX_ERROR_MEMORY] = "memory allocation failure",
  [MEX_ERROR_LEX] = "lexical error"
};

char *idsa_mex_error(IDSA_MEX_STATE * m)
{
#ifndef SAFE
  static char result[MEX_BUFFER];
#endif

  if (m->m_error >= MEX_MAX_ERROR || m->m_error == MEX_ERROR_OK) {
    return NULL;
  }
#ifdef SAFE
  result = idsa_mex_error_table[m->m_error];
#else
  snprintf(result, MEX_BUFFER - 1, "%s near line %d", idsa_mex_error_table[m->m_error], m->m_line);
  result[MEX_BUFFER - 1] = '\0';
#endif

  return result;
}

IDSA_MEX_TOKEN *idsa_mex_get(IDSA_MEX_STATE * m)
{
  IDSA_MEX_TOKEN *t;

  idsa_mex_collect(m);

  if (m->m_this) {		/* normal case, got some tokens */
    t = m->m_this;
    m->m_this = t->t_next;
  } else {
    t = NULL;
  }

  return t;
}

void idsa_mex_unget(IDSA_MEX_STATE * m, IDSA_MEX_TOKEN * t)
{
  if (t != NULL) {		/* probably unwise, but what the heck */
    m->m_this = t;
  }
}

IDSA_MEX_TOKEN *idsa_mex_peek(IDSA_MEX_STATE * m)
{
  idsa_mex_collect(m);

  return m->m_this;
}

static void idsa_mex_collect(IDSA_MEX_STATE * m)
{
  IDSA_MEX_TOKEN *t;

  if (m->m_head == NULL) {
    t = idsa_mex_token(m);
    m->m_head = t;
    m->m_this = t;
    while (t) {
#ifdef DEBUG
      fprintf(stderr, "mex_get(): lexed %d, read %d, max %d\n", m->m_lexed, m->m_read, MEX_BUFFER);
#endif
      t->t_next = idsa_mex_token(m);
      t = t->t_next;
    }
  }

}

static void idsa_mex_free(IDSA_MEX_TOKEN * t)
{
  if (t->t_buf != NULL) {
    free(t->t_buf);
    t->t_buf = NULL;
  }
  free(t);
}

static IDSA_MEX_TOKEN *idsa_mex_new(int id, int type, char *buf, int len, int line)
{
  IDSA_MEX_TOKEN *t;
  t = malloc(sizeof(IDSA_MEX_TOKEN));
  if (t) {
    t->t_id = id;
    t->t_type = type;
    t->t_next = NULL;

    if (buf && (len > 0)) {
      t->t_buf = malloc(sizeof(char) * (len + 1));
      if (t->t_buf) {
	/* FIXME: do a descape copy */
	memcpy(t->t_buf, buf, len);
	t->t_len = idsa_descape_unix(t->t_buf, len);
	t->t_buf[t->t_len] = '\0';
	t->t_line = line;
#ifdef DEBUG
	fprintf(stderr, "mex_new(): created token <%s:%d>\n", t->t_buf, t->t_len);
#endif
      } else {
	free(t);
	t = NULL;
      }
    } else {
      t->t_buf = NULL;
      t->t_len = 0;
    }
  }
  return t;
}

static IDSA_MEX_TOKEN *idsa_mex_token(IDSA_MEX_STATE * m)
{
  IDSA_MEX_TOKEN *t = NULL;
  char *ptr;
  unsigned int i, j, l;
  int state;
  int slash;

  slash = 0;
  ptr = m->m_buf;
  i = m->m_lexed;
  j = m->m_lexed;
  l = m->m_read;
  state = MEX_STATE_EATWS;

  do {
    if (i < l) {
      switch (state) {
      case MEX_STATE_EATWS:
	if (isspace(ptr[i])) {
	  if (ptr[i] == '\n') {
	    m->m_line = m->m_line + 1;
	  }
	  i++;
	  m->m_lexed = i;
	  /* stay in current state */
	} else if (m->m_keychars[(int) ptr[i]]) {
	  t = idsa_mex_new(m->m_keychars[(int) ptr[i]], IDSA_MEX_KEY, ptr + i, 1, m->m_line);
	  if (t == NULL) {
	    m->m_error = MEX_ERROR_MEMORY;
	  }
	  i++;
	  m->m_lexed = i;
	  state = MEX_STATE_QUIT;
	} else if (ptr[i] == '"') {
	  i++;
	  j = i;
	  state = MEX_STATE_STRING;
	} else if (ptr[i] == '#') {
	  i++;
	  state = MEX_STATE_EATHASH;
	} else {
	  j = i;
	  state = MEX_STATE_WORD;
	}
	break;
      case MEX_STATE_EATHASH:
	switch (ptr[i]) {
	case '\n':
	  i++;
	  m->m_line = m->m_line + 1;
	  state = MEX_STATE_EATWS;
	  m->m_lexed = i;
	  break;
	default:
	  i++;
	  break;
	}
	break;
      case MEX_STATE_WORD:
	if (isspace(ptr[i]) || m->m_keychars[(int) ptr[i]] || ptr[i] == '"' || ptr[i] == '#') {
	  t = idsa_mex_new(0, IDSA_MEX_WORD, ptr + j, i - j, m->m_line);
	  if (t == NULL) {
	    m->m_error = MEX_ERROR_MEMORY;
	  } else {
	    t->t_id = idsa_mex_lookup(m, t->t_buf);
	    if (t->t_id != 0) {
	      t->t_type = IDSA_MEX_KEY;
	    }
	  }
	  m->m_lexed = i;
	  state = MEX_STATE_QUIT;
	} else {
	  i++;
	}
	break;
      case MEX_STATE_STRING:
	switch (ptr[i]) {
	case '"':
	  if (slash) {
	    slash = 0;
	    i++;
	  } else {
	    t = idsa_mex_new(0, IDSA_MEX_STRING, ptr + j, i - j, m->m_line);
	    if (t == NULL) {
	      m->m_error = MEX_ERROR_MEMORY;
	    }
	    i++;
	    m->m_lexed = i;
	    state = MEX_STATE_QUIT;
	  }
	  break;
	case '\\':
	  slash = slash ? 0 : 1;
	  i++;
	  break;
	case '\n':
	  slash = 0;
	  m->m_line = m->m_line + 1;
	  i++;
	  break;
	default:
	  slash = 0;
	  i++;
	  break;
	}
	break;
      }
    } else {
      switch (state) {
      case MEX_STATE_EATWS:
      case MEX_STATE_EATHASH:
	break;
      case MEX_STATE_WORD:
	t = idsa_mex_new(0, IDSA_MEX_WORD, ptr + j, l - j, m->m_line);
	if (t == NULL) {
	  m->m_error = MEX_ERROR_MEMORY;
	} else {
	  t->t_id = idsa_mex_lookup(m, t->t_buf);
	  if (t->t_id != 0) {
	    t->t_type = IDSA_MEX_KEY;
	  }
	}
	m->m_lexed = l;
	break;
      default:
	m->m_error = MEX_ERROR_LEX;
	break;
      }
      state = MEX_STATE_QUIT;
    }

  } while (state != MEX_STATE_QUIT);

  return t;
}

static int idsa_mex_lookup(IDSA_MEX_STATE * m, unsigned char *s)
{
  unsigned int i;

  if (m->m_keywords == NULL) {
    return 0;
  }

  for (i = 0; (m->m_keywords[i].k_name) && strcmp(s, m->m_keywords[i].k_name); i++);

  return m->m_keywords[i].k_id;
}

void idsa_mex_dump(IDSA_MEX_STATE * m, FILE * f)
{
  IDSA_MEX_TOKEN *t;
  unsigned int i;

  fprintf(f, "line %u, read %u, lexed %u\n", m->m_line, m->m_read, m->m_lexed);
  fprintf(f, "Buffered tokens:");
  t = m->m_head;
  while (t != NULL) {
    fprintf(f, "%d:[%s:%d] ", t->t_id, t->t_buf, t->t_len);
    t = t->t_next;
  }
  fprintf(f, "\n");

  fprintf(f, "Key Words\n");
  if (m->m_keywords) {
    for (i = 0; m->m_keywords[i].k_name; i++) {
      fprintf(f, "%s:%d\n", m->m_keywords[i].k_name, m->m_keywords[i].k_id);
    }
  }

  fprintf(f, "Key Characters\n");
  for (i = 0; i < 256; i++) {
    if (m->m_keychars[i]) {
      fprintf(f, "%c ", i);
    }
  }
  fprintf(f, "\n");
}
