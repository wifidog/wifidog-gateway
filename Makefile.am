# $Header$

SUBDIRS = src . doc 

docdir = ${prefix}/share/doc/wifidog-@VERSION@

doc_DATA = \
  AUTHORS \
  COPYING \
  INSTALL \
  NEWS \
  README \
  ChangeLog
  
EXTRA_DIST = \
  wifidog.spec.in \
  wifidog.spec \
  config \
  wifidog.conf \
  phpauth

.PHONY: doc
doc:
	$(MAKE) -C doc doc
