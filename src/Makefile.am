#
# $Id$
#

bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
wifidog_LDADD = $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = commandline.c \
	conf.c \
	debug.c \
	fw_iptables.c \
	firewall.c \
	gateway.c \
	centralserver.c \
	http.c \
	auth.c \
	client_list.c \
	util.c \
	wdctl_thread.c \
	ping_thread.c \
	safe.c \
	httpd_thread.c \
	simple_http.c \
	pstring.c \
	capabilities.c
# TODO: capabilities.c is always compiled, protect with ifdef?

noinst_HEADERS = commandline.h \
	common.h \
	conf.h \
	debug.h \
	fw_iptables.h \
	firewall.h \
	gateway.h \
	centralserver.h \
	http.h \
	auth.h \
	client_list.h \
	util.h \
	wdctl_thread.h \
	wdctl.h \
	ping_thread.h \
	safe.h \
	httpd_thread.h \
	simple_http.h \
	pstring.h \
	capabilities.h

wdctl_SOURCES = wdctl.c
