# This Makefile.am is in the public domain

TESTING = testing

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

if HAVE_SQLITE
 SQLITE_DIR = sq
endif

if HAVE_POSTGRESQL
 POSTGRES_DIR = pq
endif

REST_DIR = rest


SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  lib \
	plugin \
	service \
	cli \
  statistics \
  arm \
  $(TESTING) \
  $(REST_DIR) \
  $(SQLITE_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  template \
  peerstore \
  nat \
  nat-auto \
  transport \
  core \
  nse \
  dhtu \
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
