# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  datastore.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


lib_LTLIBRARIES = \
  libgnunetdatastore.la

libgnunetdatastore_la_SOURCES = \
  datastore_api.c datastore.h
libgnunetdatastore_la_LIBADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetdatastore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 1:0:0

libexec_PROGRAMS = \
 gnunet-service-datastore

gnunet_service_datastore_SOURCES = \
 gnunet-service-datastore.c
gnunet_service_datastore_LDADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_SQLITE
if HAVE_BENCHMARKS
  SQLITE_BENCHMARKS = \
   perf_datastore_api_sqlite
endif
 SQLITE_TESTS = \
  test_datastore_api_sqlite \
  test_datastore_api_management_sqlite \
  $(SQLITE_BENCHMARKS)
endif
if HAVE_POSTGRESQL
if HAVE_BENCHMARKS
  POSTGRES_BENCHMARKS = \
   perf_datastore_api_postgres
endif
 POSTGRES_TESTS = \
  test_datastore_api_postgres \
  test_datastore_api_management_postgres \
  $(POSTGRES_BENCHMARKS)
endif

check_PROGRAMS = \
  test_datastore_api_heap \
  test_datastore_api_management_heap \
  perf_datastore_api_heap \
  $(SQLITE_TESTS) \
  $(POSTGRES_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_datastore_api_heap_SOURCES = \
 test_datastore_api.c
test_datastore_api_heap_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datastore_api_management_heap_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_heap_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

perf_datastore_api_heap_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_heap_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datastore_api_sqlite_SOURCES = \
 test_datastore_api.c
test_datastore_api_sqlite_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datastore_api_management_sqlite_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_sqlite_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

perf_datastore_api_sqlite_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_sqlite_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datastore_api_postgres_SOURCES = \
 test_datastore_api.c
test_datastore_api_postgres_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_datastore_api_management_postgres_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_postgres_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

perf_datastore_api_postgres_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_postgres_LDADD = \
 $(top_builddir)/src/service/testing/libgnunettesting.la \
 libgnunetdatastore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
 test_defaults.conf \
 test_datastore_api_data_sqlite.conf \
 test_datastore_api_data_heap.conf \
 test_datastore_api_data_postgres.conf
