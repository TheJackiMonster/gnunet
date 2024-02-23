# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_peerstore_sqlite.la
SQLITE_TESTS = test_plugin_peerstore_sqlite
libgnunet_plugin_peerstore_sqlite_la_SOURCES = \
  plugin_peerstore_sqlite.c
libgnunet_plugin_peerstore_sqlite_la_LIBADD = \
  $(top_builddir)/src/lib/sq/libgnunetsq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_peerstore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN)

test_plugin_peerstore_sqlite_SOURCES = \
  test_plugin_peerstore.c
test_plugin_peerstore_sqlite_LDADD = \
	$(top_builddir)/src/service/testing/libgnunettesting.la \
	$(top_builddir)/src/lib/util/libgnunetutil.la

check_PROGRAMS = \
 $(SQLITE_TESTS)

EXTRA_DIST = \
 test_plugin_peerstore_sqlite.conf

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif
