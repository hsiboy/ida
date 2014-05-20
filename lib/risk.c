/****************************************************************************/
/*                                                                          */
/* For a draft on the risk semantics, please look at doc/theory/risks       */
/*                                                                          */
/* risks are implemented as integers, making things somewhat more complex   */
/* but more reliable                                                        */
/*                                                                          */
/****************************************************************************/

#include <stdlib.h>
#include <ctype.h>

#include <idsa_internal.h>

#define PX 1000			/* precision, not as digits but as positive part of range divisible by 10 */

/*
severity_(PX=10):  -10 9 8 7 6 5 4 3 2 1 0 1 2 3 4 5 6 7 8 9 10+ => 21 = PX*2+1
confidence_(PX=10): 0 1 2 3 4 5 6 7 8 9 10                       => 11 = PX+1
*/

unsigned int idsa_risk_parse(const char *s)
{
  unsigned int sev, cnf, z, i, n;

  sev = PX;			/* default is zero severity */
  cnf = 0;			/* default is no confidence */

  if (s[0] == '-') {		/* severity is negative */
    n = (-1);
    i = 1;
  } else {			/* positive */
    n = 1;
    i = 0;
  }

  if (s[i] == '1') {		/* border cases, min or max */
    sev = (n == 1) ? 2 * PX : 0;
  } else if (s[i] == '0') {	/* inbetween */
    sev = PX;
    i++;
    if (s[i] == '.') {
      i++;
      z = PX / 10;
      while (isdigit(s[i]) && (z > 0)) {
	sev = sev + ((s[i] - '0') * z * n);	/* adjust towards border */
	i++;
	z = z / 10;
      }
    }
  }
  /* else something weird */
  while ((s[i] != '\0') && (s[i] != '/')) {	/* go find confidence */
    i++;
  }

  if (s[i] == '/') {		/* found confidence */
    i++;
    if (s[i] == '1') {		/* maximum */
      cnf = PX;
    } else if (s[i] == '0') {	/* start at minimum */
      cnf = 0;
      i++;
      if (s[i] == '.') {
	i++;
	z = PX / 10;
	while (isdigit(s[i]) && (z > 0)) {
	  cnf = cnf + ((s[i] - '0') * z);	/* adjust upwards */
	  i++;
	  z = z / 10;
	}
      }
    }
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_risk_parse(%s): severity=%u/%u, confidence=%u/%u\n", s, sev, 2 * PX, cnf, PX);
#endif

  return ((sev & 0xffff) << 16) | (cnf & 0xffff);
}


int idsa_risk_put(unsigned int x, char *s, int l)
{
  int y, i;
  unsigned int sev, cnf;

  sev = ((x >> 16) & 0xffff) % (2 * PX + 1);
  cnf = (x & 0xffff) % (PX + 1);

  if (l < 1) {
    return -1;
  }

  if (sev < PX) {
    s[0] = '-';
    i = 1;
  } else {
    i = 0;
  }

  if ((sev == 2 * PX) || (sev == 0)) {
    y = snprintf(s + i, l - i, "1.000/");
  } else {
    y = snprintf(s + i, l - i, "0.%03d/", (sev < PX) ? PX - sev : sev - PX);
  }

  if (y < 0 || y > (l + i)) {
    return -1;
  }

  i += y;

  if (cnf == PX) {
    y = snprintf(s + i, l - i, "1.000");
  } else {
    y = snprintf(s + i, l - i, "0.%03d", cnf);
  }

  if (y < 0 || y > (l + i)) {
    return -1;
  }
#ifdef DEBUG
  fprintf(stderr, "idsa_risk_put(%u=%u/%u,%u/%u): %s\n", x, sev, 2 * PX, cnf, PX, s);
#endif

  return 0;
}

unsigned int idsa_risk_make(double severity, double confidence)
{
  unsigned int sev, cnf;

  if (severity >= 1.0) {
    sev = 2 * PX;
  } else if (severity <= (-1.0)) {
    sev = 0;
  } else {
    sev = PX + (PX * severity);
  }

  if (confidence >= 1.0) {
    cnf = PX;
  } else if (confidence <= 0.0) {
    cnf = 0;
  } else {
    cnf = PX * confidence;
  }

#ifdef DEBUG
  fprintf(stderr, "idsa_risk_make(%f,%f): severity=%u/%u, confidence=%u/%u\n", severity, confidence, sev, 2 * PX, cnf, PX);
#endif

  return ((sev & 0xffff) << 16) | (cnf & 0xffff);
}

double idsa_risk_severity(unsigned int risk)
{
  double sev, result;

  sev = ((risk >> 16) & 0xffff) % (2 * PX + 1);
  result = (sev - PX) / PX;

#ifdef DEBUG
  fprintf(stderr, "idsa_risk_severity(%u): %f\n", risk, result);
#endif

  return result;
}

double idsa_risk_confidence(unsigned int risk)
{
  double cnf, result;

  cnf = (risk & 0xffff) % (PX + 1);
  result = cnf / PX;

#ifdef DEBUG
  fprintf(stderr, "idsa_risk_confidence(%u): %f\n", risk, result);
#endif

  return result;
}

int idsa_risk_cmp(unsigned int x, unsigned int y)
{
  unsigned int diff, range, xs, ys, xc, yc;
  int result;

  if (x == y) {
    result = IDSA_COMPARE_EQUAL | IDSA_COMPARE_INTERSECT;
  } else {

    /* WARNING: assumes that sizeof(int)>=32 */

    xs = (x >> 16) & 0xffff;
    ys = (y >> 16) & 0xffff;

    xc = (0xffff & x);
    yc = (0xffff & y);

    if (xs > ys) {
      result = IDSA_COMPARE_MORE;
      diff = xs - ys;
    } else {
      result = IDSA_COMPARE_LESS;
      diff = ys - xs;
    }
    range = (PX - xc) + (PX - yc);

#ifdef DEBUG
    fprintf(stderr, "idsa_risk_compare(): x=%u y=%u xp=%u yp=%u xc=%u yc=%u diff=%u range=%u\n", x, y, xs, ys, xc, yc, diff, range);
#endif

    if (range > diff) {
      result |= IDSA_COMPARE_INTERSECT;
    } else {
      result |= IDSA_COMPARE_DISJOINT;
    }
  }

  return result;
}
