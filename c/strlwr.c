/* strlwr.c
 *
 * Written by William D. Herrin, herrin@dirtside.com
 * Released to the public domain in 2004.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowercase.h"

char *staticstrlwr (const char *ext)
/* Changes ext to lower case and trims at 8 characters. */
{
  static char extlc[11], *p;
  static int i;

  for (i=0,p=extlc; (i<10)&&(*ext!=0) ; i++,ext++,p++)
        *p = lowercasemap[ (int) ((unsigned char) *ext) ];
  *p = 0;
  extlc[8]=0;
  return extlc;
}

int main (int argc, char **argv)
{
  char *s;
  int max, i, cur;

  s = (char*) malloc (sizeof(char)*1000);
  max=1000;
  if (argc>1) {
    cur=0;
    for (i=1; i<argc; i++) {
      if ((strlen(argv[i])+cur)>max) {
        s = (char*) realloc (s,sizeof(char) * ((max+strlen(argv[i]))*2));
      }
      s[cur]=' ';
      strcpy (s+cur+1,argv[i]);
      cur = strlen(s);
    }
    strlwr (s);
    printf ("%s\n",s+1);
  } else {
    while (!feof(stdin)) {
      s[0]=0;
      fgets (s,max,stdin);
      if (s[0]==0) continue;
      strlwr (s);
      printf ("%s",s);
    }
  }
  free (s);
  return 0;
}

