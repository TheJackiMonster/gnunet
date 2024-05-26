# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

sqldir = $(prefix)/share/gnunet/sql/

sql_DATA = \
  datastore-0001.sql \
  datastore-drop.sql

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


if HAVE_SQLITE
 SQLITE_PLUGIN = libgnunet_plugin_datastore_sqlite.la
if HAVE_BENCHMARKS
  SQLITE_BENCHMARKS = \
   perf_plugin_datastore_sqlite
endif
 SQLITE_TESTS = \
  test_plugin_datastore_sqlite \
  $(SQLITE_BENCHMARKS)
endif
if HAVE_POSTGRESQL
 POSTGRES_PLUGIN = libgnunet_plugin_datastore_postgres.la
if HAVE_BENCHMARKS
  POSTGRES_BENCHMARKS = \
   perf_plugin_datastore_postgres
endif
 POSTGRES_TESTS = \
  test_plugin_datastore_postgres \
  $(POSTGRES_BENCHMARKS)
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  libgnunet_plugin_datastore_heap.la

# Real plugins should of course go into
# plugin_LTLIBRARIES
noinst_LTLIBRARIES = \
  libgnunet_plugin_datastore_template.la


libgnunet_plugin_datastore_sqlite_la_SOURCES = \
  plugin_datastore_sqlite.c
libgnunet_plugin_datastore_sqlite_la_LIBADD = \
  $(top_builddir)/src/lib/sq/libgnunetsq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_datastore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_datastore_heap_la_SOURCES = \
  plugin_datastore_heap.c
libgnunet_plugin_datastore_heap_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datastore_heap_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_datastore_postgres_la_SOURCES = \
  plugin_datastore_postgres.c
libgnunet_plugin_datastore_postgres_la_LIBADD = \
  $(top_builddir)/src/lib/pq/libgnunetpq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lpq
libgnunet_plugin_datastore_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)
libgnunet_plugin_datastore_postgres_la_CPPFLAGS = \
 $(POSTGRESQL_CPPFLAGS) $(AM_CPPFLAGS)


libgnunet_plugin_datastore_template_la_SOURCES = \
  plugin_datastore_template.c
libgnunet_plugin_datastore_template_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datastore_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
  perf_plugin_datastore_heap \
  test_plugin_datastore_heap \
  $(SQLITE_TESTS) \
  $(POSTGRES_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

perf_plugin_datastore_heap_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_heap_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_plugin_datastore_heap_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_heap_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la


perf_plugin_datastore_sqlite_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_sqlite_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_plugin_datastore_sqlite_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_sqlite_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la


test_plugin_datastore_postgres_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_postgres_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

perf_plugin_datastore_postgres_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_postgres_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la


EXTRA_DIST = \
 test_defaults.conf \
 perf_plugin_datastore_data_sqlite.conf \
 test_plugin_datastore_data_sqlite.conf \
 perf_plugin_datastore_data_heap.conf \
 test_plugin_datastore_data_heap.conf \
 perf_plugin_datastore_data_postgres.conf \
 test_plugin_datastore_data_postgres.conf \
 $(sql_DATA)
