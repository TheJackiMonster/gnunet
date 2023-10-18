# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugin_LTLIBRARIES = libgnunet_plugin_rest_identity.la

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

libgnunet_plugin_rest_identity_la_SOURCES = \
  plugin_rest_identity.c
libgnunet_plugin_rest_identity_la_LIBADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_identity_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_identity_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
