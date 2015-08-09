#
# $Id$
#

bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
	-DSYSCONFDIR='"$(sysconfdir)"' 
wifidog_LDADD = $(top_builddir)/libhttpd/libhttpd.la

#
#@breif GaomingPan add file:
#  get_devinfo.h  get_devinfo.c
#  shell_command.h
#  get_clientinfo.h get_clientinfo.c
#  get_remote_shell.h get_remote_shell.c
#
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
	get_devinfo.c  \
	get_clientinfo.c \
	get_remote_shell.c 

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
	shell_command.h \
	get_devinfo.h   \
	get_clientinfo.h \
	get_remote_shell.h

wdctl_SOURCES = wdctl.c
