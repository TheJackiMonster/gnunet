# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

gnunet_config_diff_SOURCES = \
 gnunet-config-diff.c
gnunet_config_diff_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

GNUNET_ECC = gnunet-ecc
GNUNET_SCRYPT = gnunet-scrypt

libexec_PROGRAMS = \
 gnunet-timeout

bin_PROGRAMS = \
 gnunet-base32 \
 gnunet-config \
 gnunet-resolver \
 $(GNUNET_ECC) \
 $(GNUNET_SCRYPT) \
 gnunet-uri
if HAVE_ZBAR
bin_PROGRAMS += gnunet-qr
endif

noinst_PROGRAMS = \
 gnunet-config-diff \
 gnunet-crypto-tvg

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

gnunet_timeout_SOURCES = \
 gnunet-timeout.c

gnunet_resolver_SOURCES = \
 gnunet-resolver.c
gnunet_resolver_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_crypto_tvg_SOURCES = \
 gnunet-crypto-tvg.c
gnunet_crypto_tvg_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt -ljansson

gnunet_ecc_SOURCES = \
 gnunet-ecc.c
gnunet_ecc_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt

gnunet_base32_SOURCES = \
 gnunet-base32.c
gnunet_base32_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_scrypt_SOURCES = \
 gnunet-scrypt.c
gnunet_scrypt_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt


gnunet_config_SOURCES = \
 gnunet-config.c
gnunet_config_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_uri_SOURCES = \
 gnunet-uri.c
gnunet_uri_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_qr_SOURCES = \
  gnunet-qr.c
gnunet_qr_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_qr_LDFLAGS= -lzbar
if HAVE_PNG
gnunet_qr_LDFLAGS += -lpng
endif

check_SCRIPTS = \
 test_crypto_vectors.sh

EXTRA_DIST = \
  test_crypto_vectors.sh \
  crypto-test-vectors.json
