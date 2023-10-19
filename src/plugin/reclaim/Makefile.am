# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


CREDENTIAL_PLUGIN = \
  libgnunet_plugin_reclaim_credential_jwt.la

if HAVE_PABC
  CREDENTIAL_PLUGIN += libgnunet_plugin_reclaim_credential_pabc.la
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_reclaim.la \
  libgnunet_plugin_reclaim_attribute_basic.la \
  $(CREDENTIAL_PLUGIN)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

libgnunet_plugin_gnsrecord_reclaim_la_SOURCES = \
  plugin_gnsrecord_reclaim.c
libgnunet_plugin_gnsrecord_reclaim_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_reclaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_reclaim_attribute_basic_la_SOURCES = \
  plugin_reclaim_attribute_basic.c
libgnunet_plugin_reclaim_attribute_basic_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_basic_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

if HAVE_PABC
libgnunet_plugin_reclaim_credential_pabc_la_SOURCES = \
  plugin_reclaim_credential_pabc.c \
  pabc_helper.c \
	pabc_helper.h
libgnunet_plugin_reclaim_credential_pabc_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  -ljansson\
  -lpabc \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_credential_pabc_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
endif


libgnunet_plugin_reclaim_credential_jwt_la_SOURCES = \
  plugin_reclaim_credential_jwt.c
libgnunet_plugin_reclaim_credential_jwt_la_LIBADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  -ljansson\
  $(LTLIBINTL)
libgnunet_plugin_reclaim_credential_jwt_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
