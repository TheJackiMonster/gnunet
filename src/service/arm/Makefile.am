# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  arm.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugindir = $(libdir)/gnunet

lib_LTLIBRARIES = \
  libgnunetarm.la \
  libgnunettestingarm.la

libgnunetarm_la_SOURCES = \
  arm_api.c \
  arm_monitor_api.c \
  arm.h
libgnunetarm_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetarm_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 2:0:0

libgnunettestingarm_la_SOURCES = \
  testing_arm_cmd_start_peer.c \
  testing_arm_cmd_stop_peer.c \
  testing_arm_traits.c
libgnunettestingarm_la_LIBADD = \
  libgnunetarm.la \
  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunettestingarm_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


noinst_PROGRAMS = \
 mockup-service

libexec_PROGRAMS = \
 gnunet-service-arm

gnunet_service_arm_SOURCES = \
 gnunet-service-arm.c
gnunet_service_arm_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

mockup_service_SOURCES = \
  mockup-service.c
 mockup_service_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la
mockup_service_LDFLAGS = \
 $(GN_LIBINTL)


check_PROGRAMS = \
 test_arm_api \
 test_exponential_backoff \
 test_gnunet_service_arm

check_SCRIPTS = \
  test_arm_probnat.sh

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

test_arm_api_SOURCES = \
 test_arm_api.c
test_arm_api_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_exponential_backoff_SOURCES = \
 test_exponential_backoff.c
test_exponential_backoff_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_gnunet_service_arm_SOURCES = \
 test_gnunet_service_arm.c
 test_gnunet_service_arm_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_arm_api_data.conf

plugin_LTLIBRARIES = \
  libgnunet_test_arm_plugin_probnat.la

libgnunet_test_arm_plugin_probnat_la_SOURCES = \
 test_arm_plugin_probnat.c
libgnunet_test_arm_plugin_probnat_la_LIBADD = \
  libgnunettestingarm.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
  libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
