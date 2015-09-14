#
# Copyright (C) 2006,2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifidog
#PKG_VERSION:=gateway
PKG_VERSION:=20140822
PKG_RELEASE:=v1.0.0

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:= @SF/$(PKG_NAME)
#PKG_MD5SUM:=b992869cb6607d89362f2fc09a727af9
PKG_MD5SUM:=7241d86b46bbfeef54fb72e48a56dc8c

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/wifidog
#  SUBMENU:=Captive Portals
  SECTION:=wifidog
  CATEGORY:=Wifidog
#  SECTION:=net
#  CATEGORY:=Network
  DEPENDS:=+iptables-mod-extra +iptables-mod-ipopt +kmod-ipt-nat +iptables-mod-nat-extra +libpthread
  TITLE:=A wireless captive portal solution
  URL:=http://www.wifidog.org
endef

define Package/wifidog/description
	The Wifidog project is a complete and embeddable captive
	portal solution for wireless community groups or individuals
	who wish to open a free Hotspot while still preventing abuse
	of their Internet connection.
endef

define Package/wifidog/conffiles
/etc/wifidog.conf
endef

define Package/wifidog/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/init.d/wifidog $(1)/usr/bin/wifidog-init
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/GET_settings.sh   $(1)/usr/bin/GET_settings
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/dog_conf_generator.sh $(1)/usr/bin/dog_conf_generator
#	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/white_black_flush.sh $(1)/usr/bin/white_black_flush
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/DOG_monitor.sh $(1)/usr/bin/DOG_monitor
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifidog $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wdctl $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP)          $(PKG_INSTALL_DIR)/usr/lib/libhttpd.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/contrib/wifidog/files/wifidog.conf $(1)/etc/wifidog.conf.bak
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/scripts/conf/*  $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wifidog-msg.html $(1)/etc/
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/scripts/etc/devicekey $(1)etc/.devicekey
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/contrib/wifidog/files/$(PKG_NAME).init $(1)/etc/init.d/wifidog
endef

$(eval $(call BuildPackage,wifidog))
