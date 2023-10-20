# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

sqldir = $(prefix)/share/gnunet/sql/

sql_DATA = \
  datacache-0001.sql \
  datacache-drop.sql


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_SQLITE
  SQLITE_PLUGIN = libgnunet_plugin_datacache_sqlite.la
endif
if HAVE_POSTGRESQL
  POSTGRES_PLUGIN = libgnunet_plugin_datacache_postgres.la
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  libgnunet_plugin_datacache_heap.la

# Real plugins should of course go into
# plugin_LTLIBRARIES
noinst_LTLIBRARIES = \
  libgnunet_plugin_datacache_template.la


libgnunet_plugin_datacache_sqlite_la_SOURCES = \
  plugin_datacache_sqlite.c
libgnunet_plugin_datacache_sqlite_la_LIBADD = \
  $(top_builddir)/src/lib/sq/libgnunetsq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_datacache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_heap_la_SOURCES = \
  plugin_datacache_heap.c
libgnunet_plugin_datacache_heap_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datacache_heap_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_postgres_la_SOURCES = \
  plugin_datacache_postgres.c
libgnunet_plugin_datacache_postgres_la_LIBADD = \
  $(top_builddir)/src/lib/pq/libgnunetpq.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_PLUGIN_LDFLAGS) -lpq
libgnunet_plugin_datacache_postgres_la_CPPFLAGS = \
 $(POSTGRESQL_CPPFLAGS) $(AM_CPPFLAGS)
libgnunet_plugin_datacache_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

libgnunet_plugin_datacache_template_la_SOURCES = \
  plugin_datacache_template.c
libgnunet_plugin_datacache_template_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datacache_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


EXTRA_DIST = \
 $(sql_DATA)
