# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-core

gnunet_core_SOURCES = \
 gnunet-core.c
gnunet_core_LDADD = \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_core_LDFLAGS = \
  $(GN_LIBINTL)
