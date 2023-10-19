# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

sqldir = $(prefix)/share/gnunet/sql/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

REST_PLUGIN = libgnunet_plugin_rest_namestore.la

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  $(REST_PLUGIN)


libgnunet_plugin_rest_namestore_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_namestore_la_LIBADD = \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecordjson.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_namestore_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_namestore_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


check_SCRIPTS = \
  test_plugin_rest_namestore.sh

EXTRA_DIST = \
  $(check_SCRIPTS)
