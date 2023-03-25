# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
CFLAGS= -O2 -Wall -g -fno-strict-aliasing
#For debugging
# CFLAGS= -g -Wall
#LIBS= /usr/lib/libc_p.a /usr/lib/libg.a
ACFLAGS=$(shell apxs2 -q CFLAGS)
AINCLUDE=-I${shell apxs2 -q INCLUDEDIR)

RM= /bin/rm -f
#--- You shouldn't have to edit anything else. ---

#LIBEXECDIR=`apxs2 -q LIBEXECDIR 2>>/dev/null`

.c.o: 
	$(CC) -c $(CFLAGS) $<

PROGS=strlwr mod_include_counter


OBJS_STRLWR=strlwr.o lowercase.o

all: $(PROGS)

strlwr: $(OBJS_STRLWR)
	$(CC) $(OBJS_STRLWR) -o $@

mod_include_counter: 
	apxs2 -i -S LIBEXECDIR=`pwd` "-Wc,$(CFLAGS)" -c mod_include_counter.c counter.c lowercase.c

install: all

clean:
	rm -f *.o *.lo *.slo *.so $(PROGS)

