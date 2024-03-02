# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  core.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_test_core_plugin_cmd_just_run.la

TESTING_LIBS = \
  libgnunetcoretesting.la

lib_LTLIBRARIES = \
  libgnunetcore.la \
  $(TESTING_LIBS)

libgnunetcore_la_SOURCES = \
  core_api.c core.h \
  core_api_monitor_peers.c
libgnunetcore_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0

libgnunet_test_core_plugin_cmd_just_run_la_SOURCES = \
 test_core_plugin_cmd_just_run.c
libgnunet_test_core_plugin_cmd_just_run_la_LIBADD = \
  libgnunetcoretesting.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/transport/libgnunettransporttesting2.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_core_plugin_cmd_just_run_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunetcoretesting_la_SOURCES = \
  core_api_cmd_connecting_peers.c 
libgnunetcoretesting_la_LIBADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/transport/libgnunettransporttesting2.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunetcoretesting_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-core

gnunet_service_core_SOURCES = \
 gnunet-service-core.c gnunet-service-core.h \
 gnunet-service-core_kx.c gnunet-service-core_kx.h \
 gnunet-service-core_sessions.c gnunet-service-core_sessions.h \
 gnunet-service-core_typemap.c gnunet-service-core_typemap.h
gnunet_service_core_LDADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(Z_LIBS)


TESTING_TESTS = \
  test_core_api_send_to_self

check_PROGRAMS = \
 test_core_api_start_only \
 $(TESTING_TESTS)

# Only test TNG if we run experimental
#check_SCRIPTS= \
#  test_core_start_testcase.sh

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS) \
 $(check_SCRIPTS)
endif

test_core_api_send_to_self_SOURCES = \
 test_core_api_send_to_self.c
test_core_api_send_to_self_LDADD = \
 libgnunetcore.la \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_core_api_start_only_SOURCES = \
 test_core_api_start_only.c
test_core_api_start_only_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetcore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_core_start_testcase.sh \
  test_core_defaults.conf \
  test_core_api_data.conf \
  test_core_api_peer1.conf \
  test_core_api_peer2.conf \
  test_core_api_send_to_self.conf \
  test_core_quota_asymmetric_recv_limited_peer1.conf \
  test_core_quota_asymmetric_recv_limited_peer2.conf \
  test_core_quota_asymmetric_send_limit_peer1.conf \
  test_core_quota_asymmetric_send_limit_peer2.conf \
  test_core_quota_peer1.conf \
  test_core_quota_peer2.conf
