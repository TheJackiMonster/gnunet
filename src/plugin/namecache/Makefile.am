# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

sqldir = $(prefix)/share/gnunet/sql/

sql_DATA = \
  namecache-0001.sql \
  namecache-drop.sql


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_EXPERIMENTAL
FLAT_PLUGIN = libgnunet_plugin_namecache_flat.la
FLAT_TESTS = test_plugin_namecache_flat
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_namecache_sqlite.la
SQLITE_TESTS = test_plugin_namecache_sqlite
endif

if HAVE_POSTGRESQL
POSTGRES_PLUGIN = libgnunet_plugin_namecache_postgres.la
POSTGRES_TESTS = test_plugin_namecache_postgres
endif

# testcases do not even build yet; thus: experimental!
TESTING_TESTS = \
 test_namecache_api_cache_block

if HAVE_SQLITE
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(POSTGRES_TESTS) \
 $(FLAT_TESTS) \
 $(TESTING_TESTS)
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS)
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
	$(FLAT_PLUGIN) \
  $(POSTGRES_PLUGIN)

libgnunet_plugin_namecache_flat_la_SOURCES = \
  plugin_namecache_flat.c
libgnunet_plugin_namecache_flat_la_LIBADD = \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la  \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_namecache_flat_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_namecache_sqlite_la_SOURCES = \
  plugin_namecache_sqlite.c
libgnunet_plugin_namecache_sqlite_la_LIBADD = \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la  \
  $(top_builddir)/src/lib/sq/libgnunetsq.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_namecache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_namecache_postgres_la_SOURCES = \
  plugin_namecache_postgres.c
libgnunet_plugin_namecache_postgres_la_LIBADD = \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la  \
  $(top_builddir)/src/lib/pq/libgnunetpq.la  \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_namecache_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

test_plugin_namecache_flat_SOURCES = \
 test_plugin_namecache.c
test_plugin_namecache_flat_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_plugin_namecache_sqlite_SOURCES = \
 test_plugin_namecache.c
test_plugin_namecache_sqlite_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_plugin_namecache_postgres_SOURCES = \
 test_plugin_namecache.c
test_plugin_namecache_postgres_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_plugin_namecache_sqlite.conf \
  test_plugin_namecache_postgres.conf \
  test_plugin_namecache_flat.conf \
  $(sql_DATA)
