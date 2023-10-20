# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la

libgnunet_plugin_block_dns_la_SOURCES = \
  plugin_block_dns.c
libgnunet_plugin_block_dns_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunet_plugin_block_dns_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(top_builddir)/src/block/$(GN_PLUGIN_LDFLAGS)
