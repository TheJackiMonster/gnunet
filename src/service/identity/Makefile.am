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
  identity.conf

lib_LTLIBRARIES = \
  libgnunetidentity.la


libgnunetidentity_la_SOURCES = \
  identity_api.c \
  identity_api_lookup.c \
  identity_api_suffix_lookup.c \
  identity.h
libgnunetidentity_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetidentity_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -lsodium \
  -version-info 1:0:0

libexec_PROGRAMS = \
 gnunet-service-identity

gnunet_service_identity_SOURCES = \
 gnunet-service-identity.c
gnunet_service_identity_LDADD = \
  libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)


#check_PROGRAMS = \
# test_identity

# if ENABLE_TEST_RUN
# AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
# endif


test_identity_SOURCES = \
 test_identity.c
test_identity_LDADD = \
  libgnunetidentity.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_identity.conf
