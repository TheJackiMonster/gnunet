# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include ${MHD_CFLAGS}

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_dns.la


libgnunet_plugin_gnsrecord_dns_la_SOURCES = \
  plugin_gnsrecord_dns.c
libgnunet_plugin_gnsrecord_dns_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_dns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
