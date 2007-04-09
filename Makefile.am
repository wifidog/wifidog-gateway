# $Id$

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
	
.PHONY: ipk
ipk: dist
	make -C $(OPENWRTSDK) distclean
	mkdir -p  $(OPENWRTSDK)/dl
	cp -f  ${builddir}wifidog-@VERSION@.tar.gz $(OPENWRTSDK)/dl/
	make -C ${builddir}contrib/build-openwrt-ipk/wifidog TOPDIR=$(OPENWRTSDK) PKG_MD5SUM= V=99
	@echo DONE.  If there were no errors, your package should be in: $(OPENWRTSDK)/bin/packages/
.PHONY: rpm
rpm: dist
	cp ${builddir}wifidog.spec /usr/src/RPM/SPECS
	cp ${builddir}wifidog-@VERSION@.tar.gz /usr/src/RPM/SOURCES
	rpmbuild -ta ${builddir}wifidog-@VERSION@.tar.gz

#clean-local:
#	echo "clean-local: " && pwd
#	rm -f /usr/src/RPM/SPECS/wifidog.spec
#	rm -f /usr/src/RPM/SOURCES/wifidog-@VERSION@.tar.gz
