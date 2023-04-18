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

# Note: builddeps must be run as root since it installs the dependencies
# needed to build the package
builddeps:
	sudo apt-get update
	sudo DEBIAN_FRONTEND=noninteractive mk-build-deps --install \
	  debian/control --remove \
	  --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes'
	sudo rm -f *.buildinfo *.changes


