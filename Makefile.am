# $Header$

SUBDIRS = libhttpd src . doc 

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
  scripts \
  debian/rules \
  debian/control \
  debian/changelog \
  ipkg/rules \
  wifidog.conf

.PHONY: doc
doc:
	$(MAKE) -C doc doc
	
.PHONY: ipkg
ipkg: all
	./ipkg/rules BUILDROOT=$(BUILDROOT)
