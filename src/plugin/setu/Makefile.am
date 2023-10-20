# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_setu_test.la

libgnunet_plugin_block_setu_test_la_SOURCES = \
  plugin_block_setu_test.c
libgnunet_plugin_block_setu_test_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_setu_test_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
