#
# $Header$
#

bin_PROGRAMS = wifidog
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/
wifidog_LDADD = $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	iptables.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	auth.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	iptables.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h

