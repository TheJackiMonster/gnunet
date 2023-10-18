# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_test.la

# Real plugins should of course go into
# plugin_LTLIBRARIES
noinst_LTLIBRARIES = \
  libgnunet_plugin_block_template.la

libgnunet_plugin_block_template_la_SOURCES = \
  plugin_block_template.c
libgnunet_plugin_block_template_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_template_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_block_test_la_SOURCES = \
  plugin_block_test.c
libgnunet_plugin_block_test_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la  \
  $(LTLIBINTL)
libgnunet_plugin_block_test_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

