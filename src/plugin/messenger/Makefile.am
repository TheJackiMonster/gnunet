# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_messenger.la


libgnunet_plugin_gnsrecord_messenger_la_SOURCES = \
  plugin_gnsrecord_messenger.c
libgnunet_plugin_gnsrecord_messenger_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_messenger_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


plugindir = $(libdir)/gnunet
