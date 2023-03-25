#ifndef __LOWERCASE_H
#define __LOWERCASE_H

extern const char *lowercasemap;

char *strlwr (char *s);
/* Changes s to lower case */

int strcmpi (const char *s1, const char *s2);

int strnncmpi (const char *s1, const char *s2, int max);
  /* Compare s1 and s2 in as many as max characters. If they are the same for
   * that duration (or until eol) then return so. Else return less or greater.
   * Comparison is case insensitive.
   */

int strnncmp (const char *s1, const char *s2, int max);
  /* Compare s1 and s2 in as many as max characters. If they are the same for
   * that duration (or until eol) then return so. Else return less or greater.
   */

#endif
