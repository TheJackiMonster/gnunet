# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include ${MHD_CFLAGS}

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

noinst_PROGRAMS = \
  gnunet-gnsrecord-tvg


check_PROGRAMS = \
 test_gnsrecord_crypto \
 test_gnsrecord_serialization \
 test_gnsrecord_lsd0001testvectors \
 test_gnsrecord_block_expiration \
 perf_gnsrecord_crypto

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

lib_LTLIBRARIES = \
  libgnunetgnsrecord.la \
  libgnunetgnsrecordjson.la

gnunet_gnsrecord_tvg_SOURCES = \
 gnunet-gnsrecord-tvg.c \
 gnsrecord_crypto.h
gnunet_gnsrecord_tvg_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetgnsrecord.la \
  $(GN_LIBINTL)


libgnunetgnsrecord_la_SOURCES = \
  gnsrecord.c \
  gnsrecord_serialization.c \
  gnsrecord_crypto.c \
  gnsrecord_pow.c \
  gnsrecord_misc.c
libgnunetgnsrecord_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  -lsodium \
  $(GN_LIBINTL)
libgnunetgnsrecord_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

libgnunetgnsrecordjson_la_SOURCES = \
  json_gnsrecord.c
libgnunetgnsrecordjson_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetgnsrecord.la \
  -ljansson \
  $(GN_LIBINTL)
libgnunetgnsrecordjson_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

EXTRA_DIST = \
  $(check_SCRIPTS)

test_gnsrecord_lsd0001testvectors_SOURCES = \
 test_gnsrecord_testvectors.c
test_gnsrecord_lsd0001testvectors_LDADD = \
  libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


test_gnsrecord_serialization_SOURCES = \
 test_gnsrecord_serialization.c
test_gnsrecord_serialization_LDADD = \
  libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_gnsrecord_block_expiration_SOURCES = \
 test_gnsrecord_block_expiration.c
test_gnsrecord_block_expiration_LDADD = \
  libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


test_gnsrecord_crypto_SOURCES = \
 test_gnsrecord_crypto.c
test_gnsrecord_crypto_LDADD = \
  libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


perf_gnsrecord_crypto_SOURCES = \
 perf_gnsrecord_crypto.c
perf_gnsrecord_crypto_LDADD = \
  libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
