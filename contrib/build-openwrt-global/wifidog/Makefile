#
# Copyright (C) 2006,2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifidog
PKG_VERSION:=$(shell date +%Y%m%d )
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/databeille/wifidog-gateway.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=openWRT-portable-Makefile
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/wifidog
  SUBMENU:=Captive Portals
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+iptables-mod-extra +iptables-mod-ipopt +iptables-mod-nat-extra +libpthread
  TITLE:=A wireless captive portal solution
  URL:=http://www.wifidog.org
endef

define Package/wifidog/description
	The Wifidog project is a complete and embeddable captive
	portal solution for wireless community groups or individuals
	who wish to open a free Hotspot while still preventing abuse
	of their Internet connection.
endef

define Package/wifidog/postinst
	# Setting a default version
	OPENWRT_RELEASE="WHITERUSSIAN"
	if [ "`grep 'KAMIKAZE' /etc/banner`" != "" ]; then
		OPENWRT_RELEASE="KAMIKAZE"
	elif [ "`grep 'DISTRIB_CODENAME=\"barrier_breaker\"' /etc/openwrt_release`" != "" ]; then
		OPENWRT_RELEASE="BARRIER_BREAKER"
		cat > /etc/init.d/wifidog << EOF
#!/bin/sh /etc/rc.common
# Copyright (C) 2006 OpenWrt.org
# Updated from post https://dev.openwrt.org/ticket/14761

USE_PROCD=1

START=99
EXTRA_COMMANDS="status"
EXTRA_HELP="        status Print the status of the service"

WIFIDOG_CONF=/etc/wifidog.conf


start_service() {
        procd_open_instance
        procd_set_param command /usr/bin/wifidog-init start
        procd_set_param respawn # respawn automatically if something died, be careful if you have an alternative process supervisor
        procd_set_param file \$$WIFIDOG_CONF
        procd_close_instance
}

stop_service() {
        /usr/bin/wifidog-init stop
}

status() {
        /usr/bin/wifidog-init status
}

service_triggers() {
        ### Trigger, reload service on network change
	procd_add_reload_interface_trigger "\$$(grep 'ExternalInterface' \$$WIFIDOG_CONF | grep -v ^# | awk '{print \$$2}')"
}
EOF
	fi
endef


define Package/wifidog/conffiles
/etc/wifidog.conf
endef

define Package/wifidog/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/init.d/wifidog $(1)/usr/bin/wifidog-init
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wifidog $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/wdctl $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libhttpd.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/etc/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/wifidog.conf $(1)/etc/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/wifidog-msg.html $(1)/etc/
	$(INSTALL_DIR) $(1)/etc/init.d
	### Local build
	# $(INSTALL_BIN) ./files/wifidog.init $(1)/etc/init.d/wifidog
	### Distant build
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/contrib/build-openwrt-global/wifidog/files/wifidog.init $(1)/etc/init.d/wifidog
endef

$(eval $(call BuildPackage,wifidog))
