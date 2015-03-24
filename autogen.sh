#!/bin/sh
# Run this to generate all the initial makefiles, etc.
#
# $Id$

if [ -r Makefile ]
then
	echo "Doing distclean"
	make distclean
fi

echo "Running mkdir -p config"
mkdir -p config

if [ "X"`uname` = "XDarwin" ]
then
	echo "Running glibtoolize --force"
	glibtoolize --force
else
	echo "Running libtoolize --force"
	libtoolize --force
fi

echo "Running aclocal"
aclocal
echo "Running autoheader"
autoheader
echo "Running automake -a"
automake -a
echo "Running autoconf"
autoconf
echo "Running ./configure ${POSTCONF} --enable-maintainer-mode  $conf_flags $@"
./configure ${POSTCONF} --enable-maintainer-mode $conf_flags "$@"
