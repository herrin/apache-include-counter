/* counter.c - standalone functions supporting the counter inside
 * an apache server side include
 */

#include <stdio.h> /* FILE */
#include <stdlib.h> /* NULL */
#include <string.h> /* strcpy */
#include <sys/types.h> /* off64_t in apr.h */
#include <time.h> /* time() */
#include <sys/stat.h> /* open() */
#include <fcntl.h> /* open() */
#include <unistd.h> /* write() */

#include "lowercase.h"
#include "httpd.h" /* MAX_STRING_LEN */
#include "http_log.h" /* APLOG_MARK */
#include "http_request.h" /* ap_sub_req_lookup_file */
#include "http_config.h" /* ap_set_module_config */
#include "mod_include_counter.h"
#include "apr_strings.h" /* apr_pstrdup */

#include "counter.h"

/* -------------------- Support Functions for Counter --------------------- */


extern module AP_MODULE_DECLARE_DATA include_counter_module;

char *strcpyupto (char *dest, const char *source, int max)
{
  int i;
  if (source==NULL) { 
    dest[0]=0;
    return dest;
  }
  for (i=0;(source[i]!=0)&&(i<max);i++) dest[i]=source[i];
  dest[i]=0;
  return dest;
}

void splitagent (char *agent, char *name, char *vers)
/* Take the user-agent string, such as:
 *   Mozilla/1.2N (Windows; I; 32bit)
 * and split the part before the / (Mozilla) into name, and the first 5 digits
 * (padded by zeros) after the / (12320) into vers.
 */
{
  int i,j;

  for (i=0;(agent[i]!=0)&&(agent[i]!='/')&&(i<250);i++) 
    name[i]=agent[i];
  name[i]=0;
  strcpy (vers,"00000");
  for (j=0;(agent[i]!=0)&&(j<5);i++) 
    if ((agent[i]>='0')&&(agent[i]<='9')) vers[j++]=agent[i];
  return;
}

int checkagent (char *agent, char *name, char *vers, char *add) 
/* Check the agent description against the actual agent name, and if it matche
s
 * then set add to the appropriate string to add to the string and return 1,
 * else return 0.
 * agent="MatchThisUserAgent/InsertThisIntoFilename/NumberOfVersionDigits"
 */
{
  int i,j,k;

  for (i=0;(agent[i]!=0)&&(agent[i]!='/')&&(i<250);i++) ;
  if ((agent[i]!='/')||(strnncmpi (agent,name,i)!=0)) return 0;
  for (i=i+1,j=0;(j<20)&&(agent[i]!=0)&&(agent[i]!='/');j++,i++)
    add[j] = agent[i];
  add[j]=0;
  if (agent[i]!='/') return 1;
  k=(int) strtol (agent+i+1,NULL,10);
  if (k>5) k=5;
  for (i=0;i<k;i++) add[i+j]=vers[i];
  add[i+j]=0;
  return 1;
}

/* The Counter modification is Copyright 1996-2005 William Herrin.
 * Its offered under the Apache License, Version 2.0
 * Visit my home page at http://bill.herrin.us/ or email me at
 * herrin@dirtside.com.
 *
 * This is counter patch revision 1.3.33-2
 */



/* #define LOGSSI        1 */
#ifdef LOGSSI
int ap_log_transaction (request_rec *r);
/* Aparantly I'm really not supposed to be calling log_transaction from
 * here. */

char *fixloggedssi (char *buffer, const char *lastreq, const char *virtual_url)
{
  char oldreq[MAX_STRING_LEN];
  char *p;

  if ((lastreq==NULL)||(virtual_url[0]=='/')) {
    sprintf (buffer, "SSI %s INCLUDE/0.0", virtual_url);
    return buffer;
  }
  strcpy (oldreq,lastreq);
  for (p=oldreq; (*p!='?') && (*p!=' ') && (*p!=0); p++);
  *p=0;
  for (; (*p!='/') && (p>oldreq); p--) ;
  if (*p=='/') strcpy (p+1,virtual_url);
  sprintf (buffer, "SSI %s INCLUDE/0.0", oldreq);
  return buffer;
}
#endif

int checkyesno (char *s)
/* Check if S contains yes|true|1 versus no|false|0 and return 1 or 0.
 * Return -1 if the value is invalid. */
{
  if (s==NULL) return -1;
  switch (s[0]) {
    case 'y':
    case 't':
    case 'Y':
    case 'T':
    case '1':
      return 1;
    case 'n':
    case 'f':
    case 'N':
    case 'F':
    case '0':
      return 0;
    default:
      return -1;

  }
}

void ap_ssic_get_tag_and_value(include_counter_ctx_t *ctx, char **tag,
                                     char **tag_val, int dodecode);
    
static void counter_error (
  include_counter_ctx_t *ctx, /* for gettag */
  ap_filter_t *f,
  apr_bucket_brigade *bb,
  const char *fmt,
  ...
) {
  char output[MAX_STRING_LEN], *p;
  size_t len;
  request_rec *r = f->r;
  va_list argptr;

  va_start (argptr,fmt);
  vsnprintf (output,MAX_STRING_LEN,fmt,argptr);
  va_end (argptr);
  for (p=output; *p; p++) if (*p=='%') *p='_';
  len = (size_t) (p-output);

  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,"%s",output);
  APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(
                                apr_pmemdup(ctx->pool, output,len),
                                len, ctx->pool, f->c->bucket_alloc));
  return;
}

int handle_counter(
  include_counter_ctx_t *ctx, /* for gettag */
  ap_filter_t *f,
  apr_bucket_brigade *bb
) {
    char *tag, *tag_val;
    char fn[MAX_STRING_LEN+4],*p, gfx[MAX_STRING_LEN];
    char s[MAX_STRING_LEN+6], sr[MAX_STRING_LEN+6];
    int count=0,       /* The counter itself */
      wide=0,        /* Pad to this many zeros */
      silent=0,      /* 0 = tell number, 1 = only increment, don't display */
      increment=1,   /* How much to increment by */
      max=2147000000L,  /* How high can the number go? */
      min=0,         /* How low can the number go? */
        commas=1,      /* Use commas by default */
      xth=0,         /* Do not include th after number by default */
        random=0,      /* Instead of incrementing, jump to a random amount */
      dontincr=0,    /* Don't increment because file is not right */
      rollover=0,    /* Restart at min if above max or max if below min? */
      filedes=0;     /* File descriptor for write */
    int i,j; /* Generic Counters */
    char *ith;
    request_rec *r = f->r;
    int counted=0; /* did I actually load a counter? */


    fn[0]=0;s[0]=0; p=s;
    strcpy (gfx,"#");

    while(1) {
        ap_ssic_get_tag_and_value(ctx,&tag,&tag_val,0);
        if((!tag || strcmp(tag,"done")==0)) {
          /* close of <!--#counter tag */
           if (!counted) {
            counter_error (ctx,f,bb,
                "[Counter: no valid file= in #counter]");
          }
          return APR_SUCCESS;
        }
        if(!tag_val) {
          counter_error (ctx,f,bb,
                "[Counter: unknown error in #counter]");
          return APR_SUCCESS;
        }
        if (strcmp (tag,"silent") ==0 ) {
          if (tag_val[0]==0) silent = 1-silent;
          if ((silent=checkyesno(tag_val))<0) {
            silent=0;
            counter_error (ctx,f,bb,
                "[Counter: silent=\"%s\" is invalid."
                " It should be either true or false in %s]",
                            tag_val, r->filename);
          }
          continue;
        }
        if (strcmp (tag,"increment") ==0 ) {
          if ((tag_val[0]=='r')||(tag_val[0]=='R')) random=1;
          else {
            increment = (int) strtol (tag_val,NULL,10);
            random=0;
          }
          continue;
        }
        if (strcmp (tag,"width") ==0 )
          wide = (int) strtol (tag_val,NULL,10);
        else if (strcmp (tag,"max") ==0 )
          max = (int) strtol (tag_val,NULL,10);
        else if (strcmp (tag,"min") ==0 )
          min = (int) strtol (tag_val,NULL,10);
        else if (strcmp (tag,"rollover") ==0 ) {
          if (tag_val[0]==0) rollover = 1-rollover;
          else if ((rollover=checkyesno(tag_val))<0) {
            rollover=0;
            counter_error (ctx,f,bb,
              "[Counter: rollover=\"%s\" is invalid."
              " It should be either true or false in %s]",
              tag_val,r->filename);
          }
        }
        else if (strcmp (tag,"nocommas") ==0 ) {
          if (tag_val[0]==0) commas = 1-commas;
          else if ((commas=checkyesno(tag_val))<0) {
            commas=0;
            counter_error (ctx,f,bb,
                "[Counter: nocommas=\"%s\" is invalid."
                " It should be either true or false in %s]", 
                tag_val,r->filename);
          }
        }
       else if (strcmp (tag,"ith") ==0 ) {
          if (tag_val[0]==0) xth = 1-xth;
          else if ((xth=checkyesno(tag_val))<0) {
            xth=0;
            counter_error (ctx,f,bb,
                "[Counter: xth=\"%s\" is invalid."
                " It should be either true or false in %s]",
                 tag_val,r->filename);
          }
        }
        else if (strcmp (tag,"gfx") ==0 ) {
          strncpy (gfx,tag_val,MAX_STRING_LEN);
          gfx[MAX_STRING_LEN-10]=0; /* leaving room for the counter value */
        }
        else if (strcmp (tag,"debug") ==0 ) {
          counter_error (ctx,f,bb,
              "[Counter Debug: Commas=%s, Silent=%s, Max=%i, Min=%i, "
              "RollOver=%s, Width=%i, IncrementBy=%i, Counter=%i, "
              "Filename=\"%s\"]",
              (commas==0)?"No":"Yes",(silent==0)?"No":"Yes",max,min,
                (rollover==0)?"No":"Yes",wide,increment,count,fn);
        }
        else if (strcmp (tag,"include") ==0 )
        { /* Include a file based on the counter */
          char url[MAX_STRING_LEN];
          char *newpath;
          apr_status_t rv;
          char *error_fmt = NULL;
          request_rec *rr = NULL;

          strncpy (s,tag_val,MAX_STRING_LEN);
          s[MAX_STRING_LEN-10]=0; /* leaving room for the counter value */
          for (i=0,j=0;s[i]!=0;i++)
            if (s[i]=='%') {
              if (j!=0) s[i]='-';
              else {
                if (s[i+1]!=0) s[i+1]='i';
                else s[i]='-';
                j=1;
              }
            }
          if (j==0) strcat (s,"%i");
          sprintf (url,s,count);

          /* be safe; only files in this directory or below allowed */
          rv = apr_filepath_merge(&newpath, NULL, url,
                                    APR_FILEPATH_SECUREROOTTEST |
                                    APR_FILEPATH_NOTABSOLUTE, ctx->dpool);

          if (rv != APR_SUCCESS) {
                error_fmt = "unable to include file \"%s\" in parsed file %s";
          } else {
                rr = ap_sub_req_lookup_file(newpath, r, f->next);
          }
          if (!error_fmt && rr->status != HTTP_OK) {
            error_fmt = "unable to include \"%s\" in parsed file %s";
          }
          if (!error_fmt && (ctx->flags & SSIC_FLAG_NO_EXEC) &&
            rr->content_type && strncmp(rr->content_type, "text/", 5)) {

            error_fmt = "unable to include potential exec \"%s\" in parsed "
                        "file %s";
          }
          if (rr) {
            ap_set_module_config(rr->request_config, &include_counter_module,r);
          }
        if (!error_fmt && ap_run_sub_req(rr)) {
            error_fmt = "unable to include \"%s\" in parsed file %s";
        }
        if (error_fmt) {
            counter_error (ctx,f,bb,
                 error_fmt, tag_val, r->filename);
        }
        /* Do *not* destroy the subrequest here; it may have allocated
         * variables in this r->subprocess_env in the subrequest's
         * r->pool, so that pool must survive as long as this request.
         * Yes, this is a memory leak. */

#ifdef LOGSSI
          strcpy (s,"SSI ");
          if (url[0]!='/') {
            strncat (s,url,MAX_STRING_LEN-4);
            for (p = s+strlen(s)-1;(p>s+4)&&(*p!='/');p--) *p=0;
          }
          strncat (s,url,MAX_STRING_LEN-strlen(s));
          s[MAX_STRING_LEN-1]=0;
          if (strlen(s)<MAX_STRING_LEN-15) strcat (s," INCLUDE/1.5.1");
          eog_generic(reqInfo,s,0,reqInfo->url);
#endif /* LOGSSI */
        }
        else if (strcmp (tag,"file") ==0 )
        { /* Increment and maybe display the counter */
          FILE *cf;
          char *fnp,*fnslash;

          strncpy (fn,r->filename,MAX_STRING_LEN);
          for (fnp=fnslash=fn; *fnp; fnp++) {
            if (*fnp=='/') fnslash=fnp;
          }
          snprintf (fnslash+1,MAX_STRING_LEN-((int)(fnslash-fn))-10,
            "%s.cnt",tag_val);
          sprintf (s,"%s/",fn);
          if (strstr(s, "/../") != NULL) {
            counter_error (ctx,f,bb,
              "[Counter: %s is not in or beneath the current directory "
              "in %s]",fn, r->filename);
            continue;
          }
          cf = fopen (fn,"rt");
          if (cf==NULL)
          {
            counter_error (ctx,f,bb,
                "[Counter: %s not found in %s]", fn,r->filename);
            continue;
          }
          s[0]=0;
          /*fscanf (f,"%i",&count);*/
          if( fgets (s,MAX_STRING_LEN,cf) );
          if ((s[0]>='0')&&(s[0]<='9')) count = (int) strtol (s,NULL,10);
          else {
            counter_error (ctx,f,bb,
                "[Counter: %s does not contain a number in %s]",
                fn,r->filename);
            dontincr = 1;
            continue;
          }
          fclose (cf);
          counted = 1; /* 1 means true */
          if (!random)
            count+=increment;
          else {
            srand((int) time(NULL));
            count = rand();
            count %= max+1-min;
            count += min;
          }
          if (count>max)
          {
            if (rollover==0) count=max;
            else count-=(max-min+1);
          }
          if (count<min)
          {
            if (rollover==0) count=min;
            else count+=(max-min+1);
          }
          if (!silent)
          {
            if (wide!=0) /* minimum width, use no commas */
            {
              sprintf (s,"%%.%ii",wide);
              sprintf (sr,s,count);
            /*rprintf(reqInfo,s,count);*/
            }
            else if (commas==0) /* No commas */
              /*rprintf(reqInfo,"%i",count);*/
              sprintf(sr,"%i",count);
            else /* Use commas */
            {
              i=count;
              j=0;
              if (i<0) {
                i=0-i;
                j=1;
              }
              s[20]=0;
              p=s+17;
              sprintf (p,"%.3i",i%1000);
              i/=1000;
              for (;i>0;i/=1000)
              {
                sprintf (p-4,"%.3i",i%1000);
                p--;
                *p=',';
                p-=3;
              }
              while (*p=='0') p++;
              if (*p==0) {
                 p--;
                 *p='0';
              }
              if (j) {
                p--;
                *p='-';
              }
              sprintf(sr,"%s",p);
              /*rprintf(reqInfo,"%s",p);*/
            }
            if (xth) {
              ith="th";
              i=count;
              if (i<0) i=0-i;
              if (((i%10)==1)&&(((i%100)/10)!=1)) ith="st";
              if (((i%10)==2)&&(((i%100)/10)!=1)) ith="nd";
              if (((i%10)==3)&&(((i%100)/10)!=1)) ith="rd";
              /*rprintf(reqInfo,"<SUP>%s</SUP>",ith);*/
              if (strcmp (gfx,"#")==0) 
                sprintf(sr+strlen(sr),"<SUP>%s</SUP>",ith);
              else sprintf(sr+strlen(sr),"%s",ith);
            }
            if (strcmp (gfx,"#")==0)
              APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(
                                apr_pmemdup(ctx->pool, sr,strlen(sr)),
                                strlen(sr), ctx->pool, f->c->bucket_alloc));
            else {
              for (p=sr; *p!=0; p++) {
                strcpy (s,gfx); 
                for (i=0; s[i]!=0; i++) if (s[i]=='#') s[i]=*p;
                APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(
                                apr_pmemdup(ctx->pool, s,strlen(s)),
                                strlen(s), ctx->pool, f->c->bucket_alloc));
              }
            }
          }
          if (!dontincr) {
            /* Note: use open/write instead of fopen/fprintf so that we
             * we don't clobber the counter if the disk fills up. */
            filedes = open (fn,O_RDWR);
            if (filedes<0)
            {
              counter_error (ctx,f,bb,
                "[Counter: Cannot write to %s; Cannot increment in %s]",
                fn, r->filename);
              continue;
            }
            sprintf (s,"%i\n",count); /* MAX_STRING > possible int size */
            if (write (filedes,(void*) s,(strlen(s)*sizeof(char) ))) ;
            close (filedes);
          }
          /*    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                "[Counter: checkpoint in %s]",r->filename); */
          continue;
          /* return APR_SUCCESS; */
        }
        else {
          counter_error (ctx,f,bb,
            "[Counter: Unknown tag %s=%s in %s]",
                 tag,tag_val,r->filename);
          return APR_SUCCESS;
        }
    }

    return APR_SUCCESS;
}

