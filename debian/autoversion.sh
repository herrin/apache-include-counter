#!/bin/sh

echo "RUN AUTOVERSION"
VER=`head -1 debian/changelog | sed '
	s/^[^(]*(//
	s/).*$//'`
REL=`echo $VER | sed 's/^.*-//'`
REL=`expr 0$REL + 1`
VER=`echo $VER | sed 's/-.*$//'`
dch -v $VER-$REL "increment for build"

exit 0
