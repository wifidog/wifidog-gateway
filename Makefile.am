# $Header$

SUBDIRS = libhttpd src . doc 

docdir = ${prefix}/share/doc/wifidog-@VERSION@

doc_DATA = \
  AUTHORS \
  COPYING \
  INSTALL \
  NEWS \
  README \
  FAQ \
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

.PHONY: rpm
rpm: dist
	cp ${builddir}wifidog.spec /usr/src/RPM/SPECS
	cp ${builddir}wifidog-@VERSION@.tar.gz /usr/src/RPM/SOURCES
	rpmbuild -ta ${builddir}wifidog-@VERSION@.tar.gz
	
clean-local:
	echo "clean-local: " && pwd
	rm -f /usr/src/RPM/SPECS/wifidog.spec
	rm -f /usr/src/RPM/SOURCES/wifidog-@VERSION@.tar.gz
