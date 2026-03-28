include $(TOPDIR)/rules.mk

PKG_NAME:=dgaard
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/youruser/dgaard.git
PKG_SOURCE_VERSION:=main

PKG_MAINTAINER:=Your Name <you@example.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/rust-package.mk

define Package/dgaard
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=DGA & DNS Filtering Proxy
  DEPENDS:=$(RUST_ARCH_DEPENDS) +ca-bundle
endef

define Package/dgaard/description
  A high-performance DNS proxy written in Rust with DGA detection, 
  NRD blocking, and ABP rule support for OpenWrt.
endef

$(eval $(call BuildPackage,dgaard))