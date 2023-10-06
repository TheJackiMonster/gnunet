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
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 4:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dht.la

libgnunet_plugin_block_dht_la_SOURCES = \
  plugin_block_dht.c
libgnunet_plugin_block_dht_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_dht_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libexec_PROGRAMS = \
 gnunet-service-dht

bin_PROGRAMS = \
 gnunet-dht-monitor \
 gnunet-dht-get \
 gnunet-dht-put \
 gnunet-dht-hello

#noinst_PROGRAMS = \
# gnunet-dht-profiler

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c gnunet-service-dht.h \
 gnunet-service-dht_datacache.c gnunet-service-dht_datacache.h \
 gnunet-service-dht_neighbours.c gnunet-service-dht_neighbours.h \
 gnunet-service-dht_routing.c gnunet-service-dht_routing.h
gnunet_service_dht_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/datacache/libgnunetdatacache.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lm
gnunet_service_dht_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_get_SOURCES = \
 gnunet-dht-get.c
gnunet_dht_get_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_get_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_hello_SOURCES = \
 gnunet-dht-hello.c
gnunet_dht_hello_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_hello_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_put_SOURCES = \
 gnunet-dht-put.c
gnunet_dht_put_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_put_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_monitor_SOURCES = \
 gnunet-dht-monitor.c
gnunet_dht_monitor_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_monitor_LDFLAGS = \
  $(GN_LIBINTL)

# TNG
#gnunet_dht_profiler_SOURCES = \
#  gnunet_dht_profiler.c
#gnunet_dht_profiler_LDADD = \
#  libgnunetdht.la \
#  $(top_builddir)/src/core/libgnunetcore.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
# $(top_builddir)/src/testbed/libgnunettestbed.la
#gnunet_dht_profiler_LDFLAGS = \
#  $(GN_LIBINTL)

#noinst_LIBRARIES = libgnunetdhttest.a
#
#libgnunetdhttest_a_SOURCES = \
#  dht_test_lib.c dht_test_lib.h
#libgnunetdhttest_a_LIBADD = \
# $(top_builddir)/src/util/libgnunetutil.la \
# $(top_builddir)/src/testbed/libgnunettestbed.la \
# libgnunetdht.la

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
endif

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetdht.la

EXTRA_DIST = \
  dhtu_testbed_connect.sh \
  dhtu_testbed_deploy.conf \
  dhtu_testbed_deploy.sh
