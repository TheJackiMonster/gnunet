# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


EXTRA_DIST = \
  reclaim.conf

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  reclaim.conf

lib_LTLIBRARIES = \
  libgnunetreclaim.la \
  libgnunetdid.la

libexec_PROGRAMS = \
 gnunet-service-reclaim

gnunet_service_reclaim_SOURCES = \
 gnunet-service-reclaim.c \
 gnunet-service-reclaim_tickets.c \
 gnunet-service-reclaim_tickets.h
gnunet_service_reclaim_LDADD = \
 $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/service/identity/libgnunetidentity.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
 libgnunetreclaim.la \
 $(top_builddir)/src/service/gns/libgnunetgns.la \
 $(GN_LIBINTL)

libgnunetreclaim_la_SOURCES = \
 reclaim_api.c \
 reclaim.h \
 reclaim_attribute.c \
 reclaim_attribute.h \
 reclaim_credential.c \
 reclaim_credential.h
libgnunetreclaim_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetreclaim_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0

libgnunetdid_la_SOURCES = \
  did_helper.c \
  did_helper.h \
  did_core.h \
  did_core.c
libgnunetdid_la_LIBADD = \
	$(top_builddir)/src/lib/util/libgnunetutil.la \
	$(top_builddir)/src/service/gns/libgnunetgns.la \
	$(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
	$(top_builddir)/src/service/identity/libgnunetidentity.la \
	$(top_builddir)/src/service/namestore/libgnunetnamestore.la \
	-ljansson \
  $(GN_LIBINTL) $(XLIB)
libgnunetdid_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0

test_reclaim_attribute_SOURCES = \
  test_reclaim_attribute.c
test_reclaim_attribute_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetreclaim.la \
  $(GN_LIBINTL)

test_did_helper_SOURCES = \
  test_did_helper.c
test_did_helper_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
	$(top_builddir)/src/service/gns/libgnunetgns.la \
	$(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
	$(top_builddir)/src/service/identity/libgnunetidentity.la \
	$(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  libgnunetdid.la \
  -ljansson

check_PROGRAMS = \
  test_reclaim_attribute \
  test_did_helper

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = \
  $(check_SCRIPTS) \
  $(check_PROGRAMS)
endif
