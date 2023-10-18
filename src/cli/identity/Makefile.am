# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

bin_PROGRAMS = \
 gnunet-identity

gnunet_identity_SOURCES = \
 gnunet-identity.c
gnunet_identity_LDADD = \
  $(top_builddir)/src/service/libgnunetidentity.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_SCRIPTS = \
  test_identity_messages.sh

# if ENABLE_TEST_RUN
# AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
# endif


EXTRA_DIST = \
  test_identity_messages.sh


