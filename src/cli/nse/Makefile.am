# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

bin_PROGRAMS = gnunet-nse

gnunet_nse_SOURCES = gnunet-nse.c
gnunet_nse_LDADD = \
  $(top_builddir)/src/service/nse/libgnunetnse.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIB) $(GN_LIBINTL)
