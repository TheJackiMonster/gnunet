# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_rest_copying.la \
  libgnunet_plugin_rest_config.la

libgnunet_plugin_rest_copying_la_SOURCES = \
  plugin_rest_copying.c
libgnunet_plugin_rest_copying_la_LIBADD = \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) $(MHD_LIBS)
libgnunet_plugin_rest_copying_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_copying_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)

libgnunet_plugin_rest_config_la_SOURCES = \
  plugin_rest_config.c
libgnunet_plugin_rest_config_la_LIBADD = \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) $(MHD_LIBS) -ljansson
libgnunet_plugin_rest_config_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_config_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
