#
# $Header$
#

bin_PROGRAMS = wifidog
 
bin_SCRIPTS = fw.access fw.counters fw.destroy fw.init
EXTRA_DIST = fw.access fw.counters fw.destroy fw.init

#wifidog_LDADD = $(top_builddir)/lib/libofx.la
wifidog_SOURCES = cgi.c \
	commandline.c \
	conf.c \
	debug.c \
	firewall.c \
	gateway.c \
	http.c 

noinst_HEADERS = cgi.h \
	commandline.h \
	common.h \
	conf.h \
	debug.h \
	firewall.h \
	gateway.h \
	http.h 

#AM_CPPFLAGS = \
#	-I${top_srcdir}/inc
