# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namestore.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetnamestore.la

libexec_PROGRAMS = \
 gnunet-service-namestore

libgnunetnamestore_la_SOURCES = \
  namestore_api.c \
  namestore_api_monitor.c \
  namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0

gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c
gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)

if HAVE_SQLITE
SQLITE_TESTS = \
 test_namestore_api_store_sqlite \
 test_namestore_api_store_update_sqlite \
 test_namestore_api_zone_iteration_sqlite \
 test_namestore_api_remove_sqlite \
 test_namestore_api_lookup_nick_sqlite \
 test_namestore_api_monitoring_sqlite \
 test_namestore_api_remove_not_existing_record_sqlite \
 test_namestore_api_zone_iteration_nick_sqlite \
 test_namestore_api_zone_iteration_specific_zone_sqlite \
 test_namestore_api_zone_iteration_stop_sqlite \
 test_namestore_api_monitoring_existing_sqlite \
 test_namestore_api_zone_to_name_sqlite \
 test_namestore_api_edit_records_sqlite \
 perf_namestore_api_zone_iteration_sqlite \
 perf_namestore_api_import_sqlite \
 perf_namestore_api_import_postgres
endif


if HAVE_POSTGRESQL
POSTGRES_TESTS = \
 test_namestore_api_store_postgres \
 test_namestore_api_store_update_postgres \
 test_namestore_api_remove_postgres \
 test_namestore_api_zone_iteration_postgres \
 test_namestore_api_lookup_nick_postgres \
 test_namestore_api_monitoring_postgres \
 test_namestore_api_remove_not_existing_record_postgres \
 test_namestore_api_zone_iteration_nick_postgres \
 test_namestore_api_zone_iteration_specific_zone_postgres \
 test_namestore_api_zone_iteration_stop_postgres \
 test_namestore_api_monitoring_existing_postgres \
 test_namestore_api_zone_to_name_postgres \
 perf_namestore_api_zone_iteration_postgres
if HAVE_EXPERIMENTAL
POSTGRES_TESTS += test_namestore_api_edit_records_postgres
endif
endif

#check_PROGRAMS = \
# $(SQLITE_TESTS) \
# $(POSTGRES_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

test_namestore_api_store_sqlite_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_store_postgres_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_store_update_sqlite_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_store_update_postgres_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_lookup_nick_sqlite_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_lookup_nick_postgres_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_remove_sqlite_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_sqlite_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_remove_postgres_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_postgres_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_sqlite_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_postgres_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_to_name_sqlite_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_sqlite_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_to_name_postgres_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_postgres_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_monitoring_sqlite_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_sqlite_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_namestore_api_monitoring_postgres_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_namestore_api_monitoring_existing_sqlite_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_namestore_api_monitoring_existing_postgres_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

if HAVE_EXPERIMENTAL
test_namestore_api_edit_records_postgres_SOURCES = \
 test_namestore_api_edit_records.c
test_namestore_api_edit_records_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
endif

test_namestore_api_edit_records_sqlite_SOURCES = \
 test_namestore_api_edit_records.c
test_namestore_api_edit_records_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_namestore_api_zone_iteration_sqlite_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_postgres_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

perf_namestore_api_zone_iteration_postgres_SOURCES = \
 perf_namestore_api_zone_iteration.c
perf_namestore_api_zone_iteration_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

perf_namestore_api_import_sqlite_SOURCES = \
 perf_namestore_api_import.c
perf_namestore_api_import_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

perf_namestore_api_import_postgres_SOURCES = \
 perf_namestore_api_import.c
perf_namestore_api_import_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la


perf_namestore_api_zone_iteration_sqlite_SOURCES = \
 perf_namestore_api_zone_iteration.c
perf_namestore_api_zone_iteration_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_postgres_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_specific_zone_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_specific_zone_postgres_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_sqlite_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_postgres_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_postgres_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la


EXTRA_DIST = \
  test_common.c \
  test_namestore_api.conf \
  test_namestore_api_postgres.conf \
  test_namestore_api_sqlite.conf \
  perf_namestore_api_postgres.conf \
  perf_namestore_api_sqlite.conf
