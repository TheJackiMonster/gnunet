# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  seti.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libexec_PROGRAMS = \
 gnunet-service-seti

lib_LTLIBRARIES = \
  libgnunetseti.la

gnunet_service_seti_SOURCES = \
 gnunet-service-seti.c \
 gnunet-service-seti_protocol.h
gnunet_service_seti_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  libgnunetseti.la \
  $(GN_LIBINTL)

libgnunetseti_la_SOURCES = \
  seti_api.c seti.h
libgnunetseti_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetseti_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 # test_seti_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_seti_api_SOURCES = \
 test_seti_api.c
test_seti_api_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetseti.la

EXTRA_DIST = \
  test_seti.conf
