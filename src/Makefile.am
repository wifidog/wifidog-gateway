#
# $Header$
#

bin_PROGRAMS = wifidog
 
bin_SCRIPTS = fw.access fw.counters fw.destroy fw.init
EXTRA_DIST = fw.access fw.counters fw.destroy fw.init

#wifidog_LDADD = $(top_builddir)/lib/libofx.la
wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	child.c \
	userclasses.c

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	child.h \
	userclasses.h

#AM_CPPFLAGS = \
#	-I${top_srcdir}/inc
