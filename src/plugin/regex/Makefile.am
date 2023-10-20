# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

lib_LTLIBRARIES = \
  libgnunetregexblock.la

libgnunetregexblock_la_SOURCES = \
  regex_block_lib.c regex_block_lib.h
libgnunetregexblock_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetregexblock_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 1:0:0


plugin_LTLIBRARIES = \
 libgnunet_plugin_block_regex.la

libgnunet_plugin_block_regex_la_SOURCES = \
 plugin_block_regex.c
libgnunet_plugin_block_regex_la_LIBADD = \
 libgnunetregexblock.la \
 $(top_builddir)/src/lib/block/libgnunetblock.la \
 $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunet_plugin_block_regex_la_LDFLAGS = \
 $(GN_LIBINTL) \
 $(GN_PLUGIN_LDFLAGS)
