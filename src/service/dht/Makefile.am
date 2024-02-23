# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  dht.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
 libgnunetdht.la

libgnunetdht_la_SOURCES = \
  dht_api.c dht.h
libgnunetdht_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 4:0:0


libexec_PROGRAMS = \
 gnunet-service-dht

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c gnunet-service-dht.h \
 plugin_dhtu_gnunet.c plugin_dhtu_ip.c \
 gnunet-service-dht_datacache.c gnunet-service-dht_datacache.h \
 gnunet-service-dht_neighbours.c gnunet-service-dht_neighbours.h \
 gnunet-service-dht_routing.c gnunet-service-dht_routing.h
gnunet_service_dht_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/nse/libgnunetnse.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/datacache/libgnunetdatacache.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lm
gnunet_service_dht_LDFLAGS = \
  $(GN_LIBINTL)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
endif

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/hello/libgnunethello.la \
 libgnunetdht.la

EXTRA_DIST = \
	gnunet-service-dht_clients.c \
  dhtu_testbed_connect.sh \
  dhtu_testbed_deploy.conf \
  dhtu_testbed_deploy.sh
