/* lowercase.c - functions for converting strings to lower case and making
 * case-insensitive comparisions
 *
 * Written by William D. Herrin, herrin@dirtside.com
 * Released to the public domain in 2004.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "lowercase.h"

const char *lowercasemap =
      "\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017"
      "\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037"
      " !\"#$%&'()*+,-./0123456789:;<=>?"
      "@abcdefghijklmnopqrstuvwxyz[\\]^_"
      "`abcdefghijklmnopqrstuvwxyz{|}~\177"
      "cueaaaaceeeiiiaaeaaooouu_ou\233ey\236f"
      "aiounn\246\247?\251\252\253\254\255\256\257"
      "\260\263\262\263\264\265\266\267\270\271\272\273\274\275\276\277"
      "\340\343\342\343\344\345\346\347\350\351\354\353\354\355\356\357"
      "\360\363\362\363\364\365\366\367\370\371\374\373\374\375\376\377"
      "\340\343\342\343\344\345\346\347\350\351\354\353\354\355\356\357"
      "\360\363\362\363\364\365\366\367\370\371\374\373\374\375\376\377";

/* const char *lowercasemap =
      "\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017"
      "\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037"
      " !\"#$%&'()*+,-./0123456789:;<=>?"
      "@abcdefghijklmnopqrstuvwxyz[\\]^_"
      "`abcdefghijklmnopqrstuvwxyz{|}~\177"
      "\200\201\202\203\204\205\206\207\210\211\212\213\214\215\216\217"
      "\220\223\222\223\224\225\226\227\230\231\232\233\234\235\236\237"
      "\240\243\242\243\244\245\246\247\250\251\252\253\254\255\256\257"
      "\260\263\262\263\264\265\266\267\270\271\272\273\274\275\276\277"
      "\340\343\342\343\344\345\346\347\350\351\354\353\354\355\356\357"
      "\360\363\362\363\364\365\366\367\370\371\374\373\374\375\376\377"
      "\340\343\342\343\344\345\346\347\350\351\354\353\354\355\356\357"
      "\360\363\362\363\364\365\366\367\370\371\374\373\374\375\376\377"; */

char *strlwr (char *s)
/* Changes s to lower case */
{
  char *p;

  for (p=s; (*p!=0); p++) *p = lowercasemap[ (int) ((unsigned char) *p) ];
  return s;
}

int strcmpi (const char *s1, const char *s2)
{
  char ch1, ch2;

  if ((s1==NULL)&&(s2==NULL)) return 0;
  if (s1==NULL) return -1;
  if (s2==NULL) return 1;
  while (1) {
    ch1=lowercasemap[ (int) ((unsigned char) *s1) ];
    ch2=lowercasemap[ (int) ((unsigned char) *s2) ];
    if (ch1 < ch2) return -1;
    if (ch1 > ch2) return 1;
    if (ch1==0) return 0;
    s1++;
    s2++;
  }
}

int strnncmpi (const char *s1, const char *s2, int max)
  /* Compare s1 and s2 in as many as max characters. If they are the same for
   * that duration (or until eol) then return so. Else return less or greater.
   * Comparison is case insensitive.
   */
{
  int i;
  char c1, c2;

  for (i=0; i<max; i++, s1++, s2++) {
    c1=lowercasemap[ (int) ((unsigned char) *s1) ];
    c2=lowercasemap[ (int) ((unsigned char) *s2) ];
    if (c1<c2) return -1;
    if (c1>c2) return 1;
    if (c1==0) return 0;
  }
  return 0;
}

int strnncmp (const char *s1, const char *s2, int max)
  /* Compare s1 and s2 in as many as max characters. If they are the same for
   * that duration (or until eol) then return so. Else return less or greater.
   */
{
  int i;

  for (i=0; i<max; i++) {
    if (s1[i]<s2[i]) return -1;
    if (s1[i]>s2[i]) return 1;
    if (s1[i]==0) return 0;
  }
  return 0;
}

