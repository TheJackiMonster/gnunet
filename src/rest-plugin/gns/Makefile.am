# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_LIBIDN
  LIBIDN= -lidn
else
  LIBIDN=
endif

if HAVE_LIBIDN2
  LIBIDN2= -lidn2
else
  LIBIDN2=
endif

USE_VPN = $(top_builddir)/src/service/vpn/libgnunetvpn.la

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

REST_PLUGIN = libgnunet_plugin_rest_gns.la

plugin_LTLIBRARIES = \
  $(REST_PLUGIN)


libgnunet_plugin_rest_gns_la_SOURCES = \
  plugin_rest_gns.c
libgnunet_plugin_rest_gns_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecordjson.la \
  $(top_builddir)/src/service/gns/libgnunetgns.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_gns_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


check_SCRIPTS = \
  test_plugin_rest_gns.sh

EXTRA_DIST = \
  test_plugin_rest_gns.sh

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
