# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

sqldir = $(prefix)/share/gnunet/sql/

sql_DATA = \
  namestore-0001.sql \
  namestore-drop.sql

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif




plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN)


libgnunet_plugin_namestore_sqlite_la_SOURCES = \
  plugin_namestore_sqlite.c
libgnunet_plugin_namestore_sqlite_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/lib/sq/libgnunetsq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_namestore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_namestore_postgres_la_SOURCES = \
  plugin_namestore_postgres.c
libgnunet_plugin_namestore_postgres_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/lib/pq/libgnunetpq.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_namestore_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_namestore_sqlite.la
SQLITE_TESTS = test_plugin_namestore_sqlite
endif


if HAVE_POSTGRESQL
POSTGRES_PLUGIN = libgnunet_plugin_namestore_postgres.la
POSTGRES_TESTS = test_plugin_namestore_postgres
endif
if HAVE_SQLITE
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(POSTGRES_TESTS)
endif

test_plugin_namestore_sqlite_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_sqlite_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_plugin_namestore_postgres_SOURCES = \
  test_plugin_namestore.c
test_plugin_namestore_postgres_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_plugin_namestore_sqlite.conf \
  test_plugin_namestore_postgres.conf \
	$(sql_DATA)

