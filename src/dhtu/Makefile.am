# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_dhtu_gnunet.la \
  libgnunet_plugin_dhtu_ip.la

libgnunet_plugin_dhtu_ip_la_SOURCES = \
  plugin_dhtu_ip.c
libgnunet_plugin_dhtu_ip_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_dhtu_ip_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



libgnunet_plugin_dhtu_gnunet_la_SOURCES = \
  plugin_dhtu_gnunet.c
libgnunet_plugin_dhtu_gnunet_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_dhtu_gnunet_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
