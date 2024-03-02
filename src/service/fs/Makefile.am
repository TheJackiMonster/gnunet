# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  fs.conf

lib_LTLIBRARIES = libgnunetfs.la

libgnunetfs_la_SOURCES = \
  fs_api.c fs_api.h fs.h \
  fs_directory.c \
  fs_dirmetascan.c \
  fs_download.c \
  fs_file_information.c \
  fs_getopt.c \
  fs_list_indexed.c \
  fs_publish.c \
  fs_publish_ksk.c \
  fs_publish_ublock.c fs_publish_ublock.h \
  fs_misc.c \
  fs_namespace.c \
  fs_search.c \
  fs_sharetree.c \
  fs_tree.c fs_tree.h \
  fs_unindex.c \
  fs_uri.c \
  meta_data.c

libgnunetfs_la_LIBADD = \
  $(top_builddir)/src/service/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB) $(LIBGCRYPT_LIBS) -lunistring

if HAVE_LIBEXTRACTOR
libgnunetfs_la_LIBADD += \
  -lextractor
endif

libgnunetfs_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 3:1:1


libexec_PROGRAMS = \
  gnunet-helper-fs-publish \
  gnunet-service-fs

noinst_PROGRAMS = \
  gnunet-daemon-fsprofiler

gnunet_helper_fs_publish_SOURCES =  \
 gnunet-helper-fs-publish.c
gnunet_helper_fs_publish_LDADD =  \
  libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_helper_fs_publish_LDADD += \
  -lextractor
endif

gnunet_daemon_fsprofiler_SOURCES =  \
 gnunet-daemon-fsprofiler.c
gnunet_daemon_fsprofiler_LDADD = \
  libgnunetfs.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_fs_SOURCES =  \
 gnunet-service-fs.c gnunet-service-fs.h \
 gnunet-service-fs_cp.c gnunet-service-fs_cp.h \
 gnunet-service-fs_indexing.c gnunet-service-fs_indexing.h \
 gnunet-service-fs_pe.c gnunet-service-fs_pe.h \
 gnunet-service-fs_pr.c gnunet-service-fs_pr.h \
 gnunet-service-fs_push.c gnunet-service-fs_push.h \
 gnunet-service-fs_put.c gnunet-service-fs_put.h \
 gnunet-service-fs_cadet_client.c gnunet-service-fs_cadet.h \
 gnunet-service-fs_cadet_server.c
gnunet_service_fs_LDADD =  \
 libgnunetfs.la \
 $(top_builddir)/src/service/dht/libgnunetdht.la \
 $(top_builddir)/src/lib/block/libgnunetblock.la \
 $(top_builddir)/src/service/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/service/cadet/libgnunetcadet.la \
 $(top_builddir)/src/service/core/libgnunetcore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
 $(GN_LIBINTL) -lm

check_PROGRAMS = \
 test_fs_directory \
 test_fs_download \
 test_fs_download_cadet \
 test_fs_download_indexed \
 test_fs_download_persistence \
 test_fs_file_information \
 test_fs_getopt \
 test_fs_list_indexed \
 test_fs_namespace \
 test_fs_namespace_list_updateable \
 test_fs_publish \
 test_fs_publish_persistence \
 test_fs_search \
 test_fs_search_with_and \
 test_fs_search_probes \
 test_fs_search_persistence \
 test_fs_start_stop \
 test_fs_unindex \
 test_fs_unindex_persistence \
 test_fs_uri \
 test_fs_meta_data \
 $(FS_BENCHMARKS)
# test_gnunet_service_fs_migration

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = test_fs_directory \
 test_fs_file_information \
 test_fs_namespace \
 test_fs_namespace_list_updateable \
 test_fs_search \
 test_fs_search_with_and \
 test_fs_search_probes \
 test_fs_search_persistence \
 test_fs_start_stop \
 test_fs_uri \
 test_fs_meta_data
endif


test_fs_directory_SOURCES = \
 test_fs_directory.c
test_fs_directory_LDADD = \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

if HAVE_LIBEXTRACTOR
test_fs_directory_LDADD += \
  -lextractor
endif


test_fs_download_SOURCES = \
 test_fs_download.c
test_fs_download_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la  \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_download_indexed_SOURCES = \
 test_fs_download.c
test_fs_download_indexed_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la  \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_download_cadet_SOURCES = \
 test_fs_download.c
test_fs_download_cadet_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la  \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_download_persistence_SOURCES = \
 test_fs_download_persistence.c
test_fs_download_persistence_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la  \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_file_information_SOURCES = \
 test_fs_file_information.c
test_fs_file_information_LDADD = \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

if HAVE_LIBEXTRACTOR
test_fs_file_information_LDADD += \
  -lextractor
endif


test_fs_getopt_SOURCES = \
 test_fs_getopt.c
test_fs_getopt_LDADD = \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_list_indexed_SOURCES = \
 test_fs_list_indexed.c
test_fs_list_indexed_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_namespace_SOURCES = \
 test_fs_namespace.c
test_fs_namespace_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_namespace_list_updateable_SOURCES = \
 test_fs_namespace_list_updateable.c
test_fs_namespace_list_updateable_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_publish_SOURCES = \
 test_fs_publish.c
test_fs_publish_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_publish_persistence_SOURCES = \
 test_fs_publish_persistence.c
test_fs_publish_persistence_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_search_SOURCES = \
 test_fs_search.c
test_fs_search_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la	\
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_search_with_and_SOURCES = \
 test_fs_search_with_and.c
test_fs_search_with_and_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la	\
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_search_probes_SOURCES = \
 test_fs_search_probes.c
test_fs_search_probes_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la	\
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_search_persistence_SOURCES = \
 test_fs_search_persistence.c
test_fs_search_persistence_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la	\
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_start_stop_SOURCES = \
 test_fs_start_stop.c
test_fs_start_stop_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_unindex_SOURCES = \
 test_fs_unindex.c
test_fs_unindex_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_unindex_persistence_SOURCES = \
 test_fs_unindex_persistence.c
test_fs_unindex_persistence_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_fs_meta_data_SOURCES = \
 test_fs_meta_data.c
test_fs_meta_data_LDADD = \
 libgnunetfs.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la


test_fs_uri_SOURCES = \
 test_fs_uri.c
test_fs_uri_LDADD = \
  libgnunetfs.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la

# TNG

#test_gnunet_service_fs_p2p_SOURCES = \
# test_gnunet_service_fs_p2p.c
#test_gnunet_service_fs_p2p_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#test_gnunet_service_fs_p2p_cadet_SOURCES = \
# test_gnunet_service_fs_p2p.c
#test_gnunet_service_fs_p2p_cadet_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#test_gnunet_service_fs_migration_SOURCES = \
# test_gnunet_service_fs_migration.c
#test_gnunet_service_fs_migration_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#perf_gnunet_service_fs_p2p_SOURCES = \
# perf_gnunet_service_fs_p2p.c
#perf_gnunet_service_fs_p2p_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#perf_gnunet_service_fs_p2p_index_SOURCES = \
# perf_gnunet_service_fs_p2p.c
#perf_gnunet_service_fs_p2p_index_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#perf_gnunet_service_fs_p2p_dht_SOURCES = \
# perf_gnunet_service_fs_p2p.c
#perf_gnunet_service_fs_p2p_dht_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#perf_gnunet_service_fs_p2p_respect_SOURCES = \
# perf_gnunet_service_fs_p2p_respect.c
#perf_gnunet_service_fs_p2p_respect_LDADD = \
#  libgnunetfstest.a \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  libgnunetfs.la  \
#  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  perf_gnunet_service_fs_p2p.conf \
  test_fs_data.conf \
  test_fs_defaults.conf \
  test_fs_download_data.conf \
  test_fs_download_indexed.conf \
  test_fs_file_information_data.conf \
  test_fs_list_indexed_data.conf \
  test_fs_namespace_data.conf \
  test_fs_publish_data.conf \
  test_fs_search_data.conf \
  test_fs_unindex_data.conf \
  test_gnunet_fs_rec_data.tgz \
  test_gnunet_service_fs_migration_data.conf \
  test_gnunet_service_fs_p2p_cadet.conf \
  test_pseudonym_data.conf
