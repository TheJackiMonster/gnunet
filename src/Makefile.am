# This Makefile.am is in the public domain

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  rps \
  abd \
  auction
endif

if BUILD_PULSE_HELPERS
CONVERSATION_DIR = conversation
else
if BUILD_GST_HELPERS
CONVERSATION_DIR = conversation
endif
endif


REST_DIR = rest


SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  lib \
	plugin \
	service \
	cli \
  statistics \
  $(REST_DIR) \
  datacache \
  datastore \
  template \
  peerstore \
  nat \
  nat-auto \
  transport \
  nse \
  dht \
  hostlist \
  topology \
  regex \
  dns \
  identity \
  namecache \
  namestore \
  cadet \
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
  messenger \
  $(EXP_DIR)
