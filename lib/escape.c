#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <idsa_internal.h>

static unsigned char *idsa_escape_table = "0123456789ABCDEF";

static unsigned char escape_unix_xdigit(unsigned int c)
{
  return idsa_escape_table[c & 0x0f];
}

static int descape_unix_xdigit(unsigned char c)
{
  switch (c) {
  case '0':
    return 0;
  case '1':
    return 1;
  case '2':
    return 2;
  case '3':
    return 3;
  case '4':
    return 4;
  case '5':
    return 5;
  case '6':
    return 6;
  case '7':
    return 7;
  case '8':
    return 8;
  case '9':
    return 9;
  case 'a':
  case 'A':
    return 10;
  case 'b':
  case 'B':
    return 11;
  case 'c':
  case 'C':
    return 12;
  case 'd':
  case 'D':
    return 13;
  case 'e':
  case 'E':
    return 14;
  case 'f':
  case 'F':
    return 15;
  default:
    return 16;
  }
}

#define is_unix_special(c)   (((c)=='\\')||((c)=='"')||((c)=='^'))
#define is_unix_control(c)   (((c)<0x20)||((c)==0x7f))
#define is_unix_high(c)      ((c)&0x80)

#ifdef IDSA_OPTIMISTIC
/* assumes only a few escape characters */

int idsa_escape_unix(unsigned char *buffer, int len, int max)
{
  int result;
  int i;

  result = len;

  for (i = 0; i < result; i++) {
    if (is_unix_high(buffer[i])) {	/* high characters are escaped as \xx */
      if (result + 2 <= max) {
	memmove(buffer + i + 2, buffer + i, result - i);
	buffer[i + 1] = escape_unix_xdigit((buffer[i] & 0xf0) >> 4);
	buffer[i + 2] = escape_unix_xdigit(buffer[i] & 0x0f);
	buffer[i] = '\\';
	i += 2;
	result += 2;
      } else {			/* buffer too short */
	result = (-1);
      }
    } else if (is_unix_special(buffer[i])) {
      if (result + 1 <= max) {
	memmove(buffer + i + 1, buffer + i, result - i);
	buffer[i] = '\\';
	i++;
	result++;
      } else {			/* buffer too short */
	result = (-1);
      }
    } else if (is_unix_control(buffer[i])) {
      if (result + 1 <= max) {
	memmove(buffer + i + 1, buffer + i, result - i);
	buffer[i + 1] = 0x40 ^ buffer[i];
	buffer[i] = '^';
	i++;
	result++;
      } else {			/* buffer too short */
	result = (-1);
      }
    }				/* else do nothing, just skip */
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_escape_unix(): escaped <");
  for (i = 0; i < result; i++)
    fputc(buffer[i], stderr);
  fprintf(stderr, ">\n");
#endif

  return result;
}

int idsa_descape_unix(unsigned char *buffer, int len)
{
  int i;
  int result;

  result = len;
  i = 0;

  while (i < result) {
    switch (buffer[i]) {
    case '\\':
      if (i + 1 < result) {
	if (isxdigit(buffer[i + 1])) {
	  if (i + 2 < result) {
	    buffer[i] = (descape_unix_xdigit(buffer[i + 1]) << 4) | descape_unix_xdigit(buffer[i + 2]);
	    result -= 2;
	    memmove(buffer + i + 1, buffer + i + 3, result - (i + 1));
	  }
	} else {
	  buffer[i] = buffer[i + 1];
	  result--;
	  memmove(buffer + i + 1, buffer + i + 2, result - (i + 1));
	}
      }
      break;
    case '^':
      if (i + 1 < result) {
	buffer[i] = 0x40 ^ (buffer[i + 1]);
	result--;
	memmove(buffer + i + 1, buffer + i + 2, result - (i + 1));
      }
      break;
    default:
      /* no escape, nothing to do */
      break;
    }
    i++;			/* always advance */
  }

  return result;
}

#else				/* ! IDSA_OPTIMISTIC - best worst case performance */

int idsa_escape_unix(unsigned char *buffer, int len, int max)
{
  int extra, result, i;
  unsigned char c;

  for (i = 0, extra = 0; i < len; i++) {
    if (is_unix_high(buffer[i])) {
      extra += 2;
    } else if (is_unix_special(buffer[i])) {
      extra++;
    } else if (is_unix_control(buffer[i])) {
      extra++;
    }
  }

  if (extra <= 0) {
    result = len;
  } else {
    if (extra + len > max) {
      result = (-1);
    } else {
      result = len + extra;
      memmove(buffer + extra, buffer, len);
      for (i = 0; i < result; i++) {
	c = buffer[i + extra];
	if (is_unix_high(c)) {
	  buffer[i++] = '\\';
	  buffer[i++] = escape_unix_xdigit((c & 0xf0) >> 4);
	  buffer[i] = escape_unix_xdigit(c & 0x0f);
	  extra -= 2;
	} else if (is_unix_special(c)) {
	  buffer[i++] = '\\';
	  buffer[i] = c;
	  extra--;
	} else if (is_unix_control(c)) {
	  buffer[i++] = '^';
	  buffer[i] = 0x40 ^ c;
	  extra--;
	} else {
	  buffer[i] = c;
	}
      }
    }
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_escape_unix(): escaped <");
  for (i = 0; i < result; i++)
    fputc(buffer[i], stderr);
  fprintf(stderr, ">\n");
#endif

  return result;
}

int idsa_descape_unix(unsigned char *buffer, int len)
{
  int i;
  int result;
  unsigned char c, d;

  result = 0;
  i = 0;

  while (i < len) {
    switch (buffer[i]) {
    case '\\':
      if (i + 1 < len) {
	c = descape_unix_xdigit(buffer[i + 1]);
	if (c > 15) {
	  buffer[result] = buffer[i + 1];
	} else {
	  if (i + 2 < len) {
	    d = descape_unix_xdigit(buffer[i + 2]);
	    buffer[result] = (c << 4) | d;
	    i++;
	  }
	}
	i++;
      }
      break;
    case '^':
      if (i + 1 < len) {
	buffer[result] = 0x40 ^ (buffer[i + 1]);
	i++;
      }
      break;
    default:
      if (result < i) {
	buffer[result] = buffer[i];
      }

      /* no escape, nothing to do */
      break;
    }
    result++;
    i++;
  }

  return result;
}

#endif

int idsa_escape_xml(unsigned char *buffer, int len, int max)
{
  /*
     <       lt      &lt;    Less than sign
     >       gt      &gt;    Greater than sign
     &       amp     &amp;   Ampersand
     "       quot    &quot;  Double quote sign
   */
  int result;
  int i;

  result = len;

  for (i = 0; i < result; i++) {
    switch (buffer[i]) {
    case '<':
      if (result + 3 <= max) {
	memmove(buffer + i + 3, buffer + i, result - i);
	memcpy(buffer + i, "&lt;", 4);
	i += 3;
	result += 3;
      } else {
	return -1;
      }
      break;
    case '>':
      if (result + 3 <= max) {
	memmove(buffer + i + 3, buffer + i, result - i);
	memcpy(buffer + i, "&gt;", 4);
	i += 3;
	result += 3;
      } else {
	return -1;
      }
      break;
    case '&':
      if (result + 4 <= max) {
	memmove(buffer + i + 4, buffer + i, result - i);
	memcpy(buffer + i, "&amp;", 5);
	i += 4;
	result += 4;
      } else {
	return -1;
      }
      break;
    case '"':
      if (result + 5 <= max) {
	memmove(buffer + i + 5, buffer + i, result - i);
	memcpy(buffer + i, "&quot;", 6);
	i += 5;
	result += 5;
      } else {
	return -1;
      }
      break;
      /* FIXME: maybe also escape , */
    default:			/* no escape required */
      break;
    }
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_escape_xml(): escaped <");
  for (i = 0; i < result; i++)
    fputc(buffer[i], stderr);
  fprintf(stderr, ">\n");
#endif

  return result;
}
