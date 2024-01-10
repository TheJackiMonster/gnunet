# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  nse.conf

lib_LTLIBRARIES = libgnunetnse.la

libgnunetnse_la_SOURCES = \
  nse_api.c nse.h
libgnunetnse_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetnse_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-nse

gnunet_service_nse_SOURCES = \
 gnunet-service-nse.c
gnunet_service_nse_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(LIBGCRYPT_LIBS) \
  -lm -lgcrypt \
  $(GN_LIBINTL)
if ENABLE_NSE_HISTOGRAM
  gnunet_service_nse_LDADD += \
    $(top_builddir)/src/testbed-logger/libgnunettestbedlogger.la
endif


if HAVE_BENCHMARKS
  MULTIPEER_TEST = test_nse_multipeer
endif

check_PROGRAMS = \
 test_nse_api \
 perf_kdf \
 $(MULTIPEER_TEST)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_nse_api_SOURCES = \
 test_nse_api.c
test_nse_api_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_nse_multipeer_SOURCES = \
 test_nse_multipeer.c
test_nse_multipeer_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  -lm

perf_kdf_SOURCES = \
 perf_kdf.c
perf_kdf_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt

EXTRA_DIST = \
  test_nse.conf \
  nse_profiler_test.conf
