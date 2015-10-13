#
# $Id$
#

<<<<<<< HEAD
noinst_LIBRARIES = libgateway.a

=======
>>>>>>> FETCH_HEAD
bin_PROGRAMS = wifidog \
	wdctl
 
AM_CPPFLAGS = \
	-I${top_srcdir}/libhttpd/ \
<<<<<<< HEAD
	-DSYSCONFDIR='"$(sysconfdir)"' \
	-Wall \
	-Wextra \
	-Wno-unused-parameter
wifidog_LDADD = libgateway.a $(top_builddir)/libhttpd/libhttpd.la

wifidog_SOURCES = main.c

libgateway_a_SOURCES = commandline.c \
=======
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
>>>>>>> FETCH_HEAD
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
<<<<<<< HEAD
	simple_http.c \
	pstring.c \
	wd_util.c
=======
	get_devinfo.c  \
	get_clientinfo.c \
	get_remote_shell.c \
	device_key.c
>>>>>>> FETCH_HEAD

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
<<<<<<< HEAD
	simple_http.h \
	pstring.h \
	wd_util.h

wdctl_LDADD = libgateway.a
=======
	shell_command.h \
	get_devinfo.h   \
	get_clientinfo.h \
	get_remote_shell.h \
	device_key.h
>>>>>>> FETCH_HEAD

wdctl_SOURCES = wdctl.c
