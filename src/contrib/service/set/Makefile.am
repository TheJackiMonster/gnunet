# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  set.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_PROGRAMS = \
 gnunet-set-ibf-profiler

libexec_PROGRAMS = \
 gnunet-service-set

lib_LTLIBRARIES = \
  libgnunetset.la

gnunet_set_ibf_profiler_SOURCES = \
 gnunet-set-ibf-profiler.c \
 ibf.c
gnunet_set_ibf_profiler_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_set_SOURCES = \
 gnunet-service-set.c gnunet-service-set.h \
 gnunet-service-set_union.c gnunet-service-set_union.h \
 gnunet-service-set_intersection.c gnunet-service-set_intersection.h \
 ibf.c ibf.h \
 gnunet-service-set_union_strata_estimator.c gnunet-service-set_union_strata_estimator.h \
 gnunet-service-set_protocol.h
gnunet_service_set_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  libgnunetset.la \
  $(GN_LIBINTL)

libgnunetset_la_SOURCES = \
  set_api.c set.h
libgnunetset_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetset_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 # test_set_api \
 # test_set_union_result_symmetric \
 # test_set_intersection_result_full \
 test_set_union_copy

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_set_api_SOURCES = \
 test_set_api.c
test_set_api_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetset.la

test_set_union_result_symmetric_SOURCES = \
 test_set_union_result_symmetric.c
test_set_union_result_symmetric_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetset.la

test_set_intersection_result_full_SOURCES = \
 test_set_intersection_result_full.c
test_set_intersection_result_full_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetset.la

test_set_union_copy_SOURCES = \
 test_set_union_copy.c
test_set_union_copy_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetset.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_set_test.la

libgnunet_plugin_block_set_test_la_SOURCES = \
  plugin_block_set_test.c
libgnunet_plugin_block_set_test_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_set_test_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


EXTRA_DIST = \
  test_set.conf
