#!/bin/sh
# Run this to generate all the initial makefiles, etc.

echo "Running mkdir -p config"
mkdir -p config
echo "Running libtoolize --force"
libtoolize --force
echo "Running aclocal"
aclocal
echo "Running autoheader"
autoheader
echo "Running automake -a"
automake -a
echo "Running autoconf"
autoconf
echo "Running ./configure --enable-maintainer-mode  $conf_flags $@"
./configure --enable-maintainer-mode $conf_flags "$@"
