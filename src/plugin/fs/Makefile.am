# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_fs.la

libgnunet_plugin_block_fs_la_SOURCES = \
  plugin_block_fs.c
libgnunet_plugin_block_fs_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_fs_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
 test_plugin_block_fs

test_plugin_block_fs_SOURCES = \
 test_plugin_block_fs.c
test_plugin_block_fs_LDADD = \
 $(top_builddir)/src/lib/block/libgnunetblock.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la
