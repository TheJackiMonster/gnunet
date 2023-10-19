# This Makefile.am is in the public domain


if BUILD_PULSE_HELPERS
CONVERSATION_DIR = conversation
else
if BUILD_GST_HELPERS
CONVERSATION_DIR = conversation
endif
endif

SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  lib \
	service \
	plugin \
	rest-plugin \
	cli \
	contrib \
  namecache \
  namestore \
  set \
  seti \
  setu \
  consensus \
  scalarproduct \
  revocation \
  vpn \
  gns \
  zonemaster \
  $(CONVERSATION_DIR) \
  fs \
  exit \
  pt \
  secretsharing \
  reclaim \
  messenger
