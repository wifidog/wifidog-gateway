# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = libhttpd src . doc 

docdir = ${prefix}/share/doc/wifidog-@VERSION@

doc_DATA = \
  AUTHORS \
  COPYING \
  NEWS \
  README.md \
  ChangeLog
  
EXTRA_DIST = \
  FAQ \
  wifidog.spec.in \
  wifidog.spec \
  config \
  scripts \
  contrib \
  wifidog.conf

.PHONY: doc
doc:
	$(MAKE) -C doc doc
