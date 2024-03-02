# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


EXTRA_DIST = \
  test_reclaim_defaults.conf \
  test_reclaim.conf \
  $(check_SCRIPTS)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

bin_PROGRAMS = \
 gnunet-reclaim \
 gnunet-did

gnunet_reclaim_SOURCES = \
 gnunet-reclaim.c
gnunet_reclaim_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

gnunet_did_SOURCES = \
	gnunet-did.c
gnunet_did_LDADD = \
	$(top_builddir)/src/lib/util/libgnunetutil.la \
	$(top_builddir)/src/service/gns/libgnunetgns.la \
	$(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
	$(top_builddir)/src/service/identity/libgnunetidentity.la \
	$(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/reclaim/libgnunetdid.la \
	-ljansson
gnunet_did_CFLAGS = \
	-I$(top_builddir)/src/service/reclaim

check_SCRIPTS = \
  test_reclaim_attribute.sh \
  test_reclaim_issue.sh \
  test_reclaim_consume.sh

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = \
  $(check_SCRIPTS) \
  $(check_PROGRAMS)
endif
