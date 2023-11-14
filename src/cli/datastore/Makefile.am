# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


bin_PROGRAMS = \
 gnunet-datastore

gnunet_datastore_SOURCES = \
 gnunet-datastore.c
gnunet_datastore_LDADD = \
  $(top_builddir)/src/service/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
