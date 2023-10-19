# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  revocation.conf

test_revocation_lsd0001testvectors_SOURCES = \
 test_revocation_testvectors.c
test_revocation_lsd0001testvectors_LDADD = \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
	$(top_builddir)/src/service/identity/libgnunetidentity.la \
  libgnunetrevocation.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

lib_LTLIBRARIES = libgnunetrevocation.la

libgnunetrevocation_la_SOURCES = \
  revocation_api.c revocation.h
libgnunetrevocation_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL) $(XLIB) -lgcrypt
libgnunetrevocation_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0

libexec_PROGRAMS = \
 gnunet-service-revocation

gnunet_service_revocation_SOURCES = \
 gnunet-service-revocation.c
gnunet_service_revocation_LDADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/setu/libgnunetsetu.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lm \
  $(GN_LIBINTL)

test_revocation_SOURCES = \
 test_revocation.c
test_revocation_LDADD = \
 $(top_builddir)/src/service/identity/libgnunetidentity.la \
 libgnunetrevocation.la \
 $(top_builddir)/src//core/libgnunetcore.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la

check_PROGRAMS = \
 #test_revocation \
 #test_revocation_lsd0001testvectors

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = \
 $(check_SCRIPTS) \
 $(check_PROGRAMS)
endif

EXTRA_DIST = test_revocation.conf
