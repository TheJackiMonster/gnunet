# This Makefile.am is in the public domain

TESTING = testing
TESTBED = testbed-logger testbed

if HAVE_EXPERIMENTAL
 EXP_DIR = \
  did
  #rps
  #abd FTBFS
if HAVE_ABE
 EXP_DIR += \
  abe
endif
 EXP_DIR += \
  auction
endif

JSON_DIR = json
CURL_DIR = curl

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

if HAVE_MYSQL
 MYSQL_DIR = mysql my
endif

if HAVE_POSTGRESQL
 POSTGRES_DIR = pq
endif

REST_DIR = rest


SUBDIRS = \
  include $(INTLEMU_SUBDIRS) \
  util \
  nt \
  hello \
  block \
  statistics \
  arm \
  $(TESTING) \
  $(JSON_DIR) \
  $(CURL_DIR) \
  $(REST_DIR) \
  peerinfo \
  $(SQLITE_DIR) \
  $(MYSQL_DIR) \
  $(POSTGRES_DIR) \
  datacache \
  datastore \
  template \
  peerstore \
  ats \
  nat \
  nat-auto \
  fragmentation \
  transport \
  ats-tool \
  core \
  $(TESTBED) \
  nse \
  dhtu \
  dht \
  hostlist \
  topology \
  regex \
  dns \
  identity \
  gnsrecord \
  namecache \
  namestore \
  peerinfo-tool \
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
  $(EXP_DIR) \
  integration-tests
