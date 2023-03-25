# For gcc
CC= gcc
# For ANSI compilers
#CC= cc

#For Optimization
CFLAGS= -O2 -Wall -g -fno-strict-aliasing
#For debugging
# CFLAGS= -g -Wall
#LIBS= /usr/lib/libc_p.a /usr/lib/libg.a

RM= /bin/rm -f

.c.o: 
	$(CC) -c $(CFLAGS) $<

all: 
	dpkg-buildpackage -b --no-sign

install: all

clean:
	dpkg-buildpackage -rfakeroot -Tclean
