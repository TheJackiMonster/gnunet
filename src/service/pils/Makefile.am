# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  pils.conf

lib_LTLIBRARIES = libgnunetpils.la

libgnunetpils_la_SOURCES = \
  pils_api.c pils.h
libgnunetpils_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetpils_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-pils

gnunet_service_pils_SOURCES = \
 gnunet-service-pils.c
gnunet_service_pils_LDADD = \
  libgnunetpils.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(LIBGCRYPT_LIBS) \
  -lm -lgcrypt \
  $(GN_LIBINTL)


check_PROGRAMS =
  #test_pils_api # disable this test - it might have been a non-viable approach

check_SCRIPTS = \
  test_pils_basic.sh

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)

endif

#test_pils_api_SOURCES = \
# test_pils_api.c
#test_pils_api_LDADD = \
#  libgnunetpils.la \
#  $(top_builddir)/src/lib/testing/libgnunettesting.la \
#  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
#  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
#  $(top_builddir)/src/service/arm/libgnunettestingarm.la \
#  #$(top_builddir)/src/service/testing/libgnunettesting.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_pils_basic.conf \
  test_pils_basic_topo.conf

plugin_LTLIBRARIES = \
  libgnunet_plugin_testing_pils_basic.la

libgnunet_plugin_testing_pils_basic_la_SOURCES = \
 test_pils_plugin_basic.c
libgnunet_plugin_testing_pils_basic_la_LIBADD = \
  $(top_builddir)/src/service/arm/libgnunettestingarm.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/service/testbed/libgnunettestingtestbed.la \
  libgnunetpils.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
