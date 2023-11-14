# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  nat-auto.conf

libexec_PROGRAMS = \
 gnunet-service-nat-auto

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetnatauto.la

libgnunetnatauto_la_SOURCES = \
  nat_auto_api.c \
  nat_auto_api_test.c
libgnunetnatauto_la_LIBADD = \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) @EXT_LIBS@
libgnunetnatauto_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

gnunet_service_nat_auto_SOURCES = \
 gnunet-service-nat-auto.c nat-auto.h
gnunet_service_nat_auto_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(GN_LIBINTL)
