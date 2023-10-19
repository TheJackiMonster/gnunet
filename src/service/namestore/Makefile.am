# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namestore.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetnamestore.la

libexec_PROGRAMS = \
 gnunet-service-namestore

libexec_PROGRAMS += \
 gnunet-namestore-fcfsd


libgnunetnamestore_la_SOURCES = \
  namestore_api.c \
  namestore_api_monitor.c \
  namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0

gnunet_namestore_fcfsd_SOURCES = \
 gnunet-namestore-fcfsd.c
gnunet_namestore_fcfsd_LDADD = $(MHD_LIBS) \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(GN_LIBINTL) -ljansson
gnunet_namestore_fcfsd_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c
gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)
