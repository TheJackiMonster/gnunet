# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

bin_PROGRAMS = \
 gnunet-cadet

gnunet_cadet_SOURCES = \
  gnunet-cadet.c
gnunet_cadet_LDADD = \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_cadet_LDFLAGS = \
  $(GN_LIBINTL)
