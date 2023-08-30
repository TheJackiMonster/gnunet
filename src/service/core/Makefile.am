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
  libgnunet_plugin_testing_core_underlay_dummy.la \
  libgnunet_plugin_testing_core_basic.la

#libgnunet_test_core_plugin_cmd_run_emu.la
#libgnunet_test_core_plugin_cmd_just_run.la

TESTING_LIBS = \
  libgnunettestingcore.la
#libgnunetcoretesting.la

UNDERLAY_DUMMY_LIBS = \
  libgnunetcoreunderlaydummy.la

lib_LTLIBRARIES = \
  libgnunetcore.la \
  libgnunettestingcore.la \
  $(UNDERLAY_DUMMY_LIBS)

#libgnunetcoretesting.la

libgnunetcore_la_SOURCES = \
  core_api.c core.h \
  core_api_monitor_peers.c
libgnunetcore_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0

libgnunettestingcore_la_SOURCES = \
  testing_core_cmd_connect.c \
  testing_core_cmd_recv.c \
  testing_core_cmd_send.c \
  testing_core_traits.c
libgnunettestingcore_la_LIBADD = \
  libgnunetcore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
  $(top_builddir)/src/service/arm/libgnunettestingarm.la \
  $(GN_LIBINTL) $(XLIB)
libgnunettestingcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


#libgnunet_test_core_plugin_cmd_run_emu_la_SOURCES = \
# test_core_plugin_cmd_run_emu.c
#libgnunet_test_core_plugin_cmd_run_emu_la_LIBADD = \
#  libgnunetcoretesting.la \
#  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
#  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
#  $(top_builddir)/src/lib/hello/libgnunethello.la \
#  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
#  $(top_builddir)/src/service/transport/libgnunettransporttesting2.la \
#  $(top_builddir)/src/service/testing/libgnunettesting.la \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/service/arm/libgnunetarm.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la \
#  $(LTLIBINTL)
#libgnunet_test_core_plugin_cmd_run_emu_la_LDFLAGS = \
#  $(GN_PLUGIN_LDFLAGS)

libgnunetcoreunderlaydummy_la_SOURCES = \
  gnunet_core_underlay_dummy.h gnunet_core_underlay_dummy.c
libgnunetcoreunderlaydummy_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la
libgnunetcoreunderlaydummy_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


#libgnunetcoretesting_la_SOURCES = \
#  core_api_cmd_connecting_peers.c
#libgnunetcoretesting_la_LIBADD = \
#  $(top_builddir)/src/service/testing/libgnunettesting.la \
#  $(top_builddir)/src/service/arm/libgnunetarm.la \
#  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
#  $(top_builddir)/src/lib/hello/libgnunethello.la \
#  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
#  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#libgnunetcoretesting_la_LDFLAGS = \
#  $(GN_LIBINTL) \
#  $(GN_LIB_LDFLAGS) \
#  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-core

# FIXME: This is not the way to go - it should only be built
# as a dependency of the testing test
bin_PROGRAMS = \
 test_core_underlay_dummy_testing_launcher


gnunet_service_core_SOURCES = \
 gnunet-service-core.c gnunet-service-core.h \
 gnunet-service-core_kx.c gnunet-service-core_kx.h \
 gnunet-service-core_sessions.c gnunet-service-core_sessions.h \
 gnunet-service-core_typemap.c gnunet-service-core_typemap.h
gnunet_service_core_LDADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/pils/libgnunetpils.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(UNDERLAY_DUMMY_LIBS) $(GN_LIBINTL) $(Z_LIBS)


#TESTING_TESTS = \
# test_core_api_send_to_self

DUMMY_TESTS = \
  test_core_underlay_dummy

check_PROGRAMS = \
 test_core_api_start_only \
 $(TESTING_TESTS) \
 $(DUMMY_TESTS)

# Only test TNG if we run experimental
#check_SCRIPTS= \
#  test_core_start_testcase.sh

check_SCRIPTS= \
  test_core_basic.sh

#  test_core_underlay_dummy_testing.sh

# FIXME: This seems not to work
check_DEPENDENCIES= \
  test_core_underlay_dummy_testing_launcher

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 $(check_PROGRAMS) \
 $(check_SCRIPTS)
endif

test_core_api_send_to_self_SOURCES = \
 test_core_api_send_to_self.c
test_core_api_send_to_self_LDADD = \
 libgnunetcore.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_core_api_start_only_SOURCES = \
 test_core_api_start_only.c
test_core_api_start_only_LDADD = \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 libgnunetcore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_core_underlay_dummy_SOURCES = \
 test_core_underlay_dummy.c
test_core_underlay_dummy_LDADD = \
 libgnunetcoreunderlaydummy.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

libgnunet_plugin_testing_core_underlay_dummy_la_SOURCES = \
  test_core_plugin_underlay_dummy.c
libgnunet_plugin_testing_core_underlay_dummy_la_LIBADD = \
  libgnunetcoreunderlaydummy.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la
# FIXME: This seems not to work
#libgnunet_plugin_testing_core_underlay_dummy_la_DEPENDENCIES = \
#  test_core_underlay_dummy_testing_launcher

test_core_underlay_dummy_testing_launcher_SOURCES = \
  test_core_underlay_dummy_testing_launcher.c
test_core_underlay_dummy_testing_launcher_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la
test_core_underlay_dummy_testing_launcher_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS)


EXTRA_DIST = \
  $(check_SCRIPTS) \
  test_core_start_testcase.sh \
  test_core_underlay_dummy.sh \
  test_core_basic_peer.conf \
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
  test_core_quota_peer2.conf \
  test_core_underlay_dummy_netjail_topo.conf

libgnunet_plugin_testing_core_basic_la_SOURCES = \
 test_core_plugin_basic.c
libgnunet_plugin_testing_core_basic_la_LIBADD = \
  libgnunettestingcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
  $(top_builddir)/src/service/arm/libgnunettestingarm.la \
  libgnunetcore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
