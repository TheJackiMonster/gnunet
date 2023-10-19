# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

bin_PROGRAMS = \
  gnunet-vpn

gnunet_vpn_SOURCES = \
 gnunet-vpn.c
gnunet_vpn_LDADD = \
  $(top_builddir)/src/service/vpn/libgnunetvpn.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
