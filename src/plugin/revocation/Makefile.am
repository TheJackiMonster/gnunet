# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_revocation.la

libgnunet_plugin_block_revocation_la_SOURCES = \
  plugin_block_revocation.c
libgnunet_plugin_block_revocation_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la  \
  $(LTLIBINTL)
libgnunet_plugin_block_revocation_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
