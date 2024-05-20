# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  datacache.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetdatacache.la

libgnunetdatacache_la_SOURCES = \
  datacache.c
libgnunetdatacache_la_LIBADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetdatacache_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0


if HAVE_SQLITE
SQLITE_TESTS = \
 test_datacache_sqlite \
 test_datacache_quota_sqlite \
 $(SQLITE_BENCHMARKS)
endif

HEAP_TESTS = \
 test_datacache_heap \
 test_datacache_quota_heap \
 $(HEAP_BENCHMARKS)

if HAVE_POSTGRESQL
POSTGRES_TESTS = \
 test_datacache_postgres \
 test_datacache_quota_postgres \
 $(POSTGRES_BENCHMARKS)
endif

check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(HEAP_TESTS) \
 $(POSTGRES_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_datacache_sqlite_SOURCES = \
 test_datacache.c
test_datacache_sqlite_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datacache_quota_sqlite_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_sqlite_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datacache_heap_SOURCES = \
 test_datacache.c
test_datacache_heap_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datacache_quota_heap_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_heap_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datacache_postgres_SOURCES = \
 test_datacache.c
test_datacache_postgres_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datacache_quota_postgres_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_postgres_LDADD = \
 libgnunetdatacache.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
 test_datacache_data_sqlite.conf \
 test_datacache_data_heap.conf \
 test_datacache_data_postgres.conf
