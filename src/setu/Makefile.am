# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  setu.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-setu-profiler

noinst_PROGRAMS = \
 gnunet-setu-ibf-profiler

libexec_PROGRAMS = \
 gnunet-service-setu

lib_LTLIBRARIES = \
  libgnunetsetu.la

gnunet_setu_profiler_SOURCES = \
 gnunet-setu-profiler.c
gnunet_setu_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  libgnunetsetu.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(GN_LIBINTL)


gnunet_setu_ibf_profiler_SOURCES = \
 gnunet-setu-ibf-profiler.c \
 ibf.c
gnunet_setu_ibf_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_setu_SOURCES = \
 gnunet-service-setu.c gnunet-service-setu_protocol.h \
 ibf.c ibf.h \
 gnunet-service-setu_strata_estimator.c gnunet-service-setu_strata_estimator.h \
 gnunet-service-setu_protocol.h
gnunet_service_setu_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  libgnunetsetu.la \
  $(GN_LIBINTL)

libgnunetsetu_la_SOURCES = \
  setu_api.c setu.h
libgnunetsetu_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetsetu_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 test_setu_api \
 perf_setu_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_setu_api_SOURCES = \
 test_setu_api.c
test_setu_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetsetu.la


perf_setu_api_SOURCES = \
 perf_setu_api.c
perf_setu_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetsetu.la


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_setu_test.la

libgnunet_plugin_block_setu_test_la_SOURCES = \
  plugin_block_setu_test.c
libgnunet_plugin_block_setu_test_la_LIBADD = \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_setu_test_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


EXTRA_DIST = \
  test_setu.conf
