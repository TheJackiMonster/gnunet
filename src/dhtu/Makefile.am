# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_dhtu_gnunet.la \
  libgnunet_plugin_dhtu_ip.la

libgnunet_plugin_dhtu_ip_la_SOURCES = \
  plugin_dhtu_ip.c
libgnunet_plugin_dhtu_ip_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_dhtu_ip_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



libgnunet_plugin_dhtu_gnunet_la_SOURCES = \
  plugin_dhtu_gnunet.c
libgnunet_plugin_dhtu_gnunet_la_LIBADD = \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_dhtu_gnunet_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


lib_LTLIBRARIES = \
  libgnunettestingdhtu.la

libgnunettestingdhtu_la_SOURCES = \
  testing_dhtu_cmd_send.c
libgnunettestingdhtu_la_LIBADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettestingdhtu_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0



test_dhtu_ip_SOURCES = \
 test_dhtu_ip.c
test_dhtu_ip_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

check_PROGRAMS = \
 test_dhtu_ip

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 $(check_PROGRAMS)
endif
