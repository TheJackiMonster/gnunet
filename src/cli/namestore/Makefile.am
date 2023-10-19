# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

sqldir = $(prefix)/share/gnunet/sql/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


bin_PROGRAMS = \
 gnunet-namestore \
 gnunet-namestore-dbtool \
 gnunet-namestore-zonefile \
 gnunet-zoneimport

gnunet_namestore_zonefile_SOURCES = \
 gnunet-namestore-zonefile.c
gnunet_namestore_zonefile_LDADD = \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_zoneimport_SOURCES = \
 gnunet-zoneimport.c
gnunet_zoneimport_LDADD = \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_namestore_SOURCES = \
 gnunet-namestore.c
gnunet_namestore_LDADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)

gnunet_namestore_dbtool_SOURCES = \
 gnunet-namestore-dbtool.c
gnunet_namestore_dbtool_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)



check_SCRIPTS = \
  test_namestore_put.sh \
  test_namestore_put_stdin.sh \
  test_namestore_lookup.sh \
  test_namestore_delete.sh \
  test_namestore_zonefile_import.sh

EXTRA_DIST = \
  example_zonefile \
  $(check_SCRIPTS)
