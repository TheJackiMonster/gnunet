# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  peerstore.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libexec_PROGRAMS = \
 gnunet-service-peerstore

lib_LTLIBRARIES = \
 libgnunetpeerstore.la

gnunet_service_peerstore_SOURCES = \
 gnunet-service-peerstore.c \
 peerstore_common.c peerstore_common.h \
 peerstore.h
gnunet_service_peerstore_CFLAGS = $(AM_CFLAGS)
gnunet_service_peerstore_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(GN_LIBINTL)

libgnunetpeerstore_la_SOURCES = \
  peerstore_api.c \
  peerstore_api_monitor.c \
  peerstore_common.c
libgnunetpeerstore_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la
libgnunetpeerstore_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 test_peerstore_api_store \
 test_peerstore_api_iterate \
 test_peerstore_api_watch \
 perf_peerstore_store

EXTRA_DIST = \
 test_peerstore_api_data.conf

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_peerstore_api_store_SOURCES = \
 test_peerstore_api_store.c
test_peerstore_api_store_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_peerstore_api_iterate_SOURCES = \
 test_peerstore_api_iterate.c
test_peerstore_api_iterate_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_peerstore_api_watch_SOURCES = \
 test_peerstore_api_watch.c
test_peerstore_api_watch_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

perf_peerstore_store_SOURCES = \
 perf_peerstore_store.c
perf_peerstore_store_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
