#
# $Header$
#

bin_PROGRAMS = wifidog
 
bin_SCRIPTS = fw.access fw.counters fw.destroy fw.init
EXTRA_DIST = fw.access fw.counters fw.destroy fw.init

AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/
wifidog_LDADD = $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	auth.c \
	userclasses.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h \
	userclasses.h

