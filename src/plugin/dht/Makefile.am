# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dht.la

libgnunet_plugin_block_dht_la_SOURCES = \
  plugin_block_dht.c
libgnunet_plugin_block_dht_la_LIBADD = \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_dht_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
