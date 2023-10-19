# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


REST_PLUGIN = \
  libgnunet_plugin_rest_reclaim.la

if HAVE_JOSE
REST_PLUGIN += libgnunet_plugin_rest_openid_connect.la
endif

if HAVE_PABC
  REST_PLUGIN += libgnunet_plugin_rest_pabc.la
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugin_LTLIBRARIES = \
  $(REST_PLUGIN)

libgnunet_plugin_rest_reclaim_la_SOURCES = \
  plugin_rest_reclaim.c \
  json_reclaim.h \
  json_reclaim.c
libgnunet_plugin_rest_reclaim_la_LIBADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_reclaim_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_reclaim_la_CFLAGS = \
	$(MHD_CFLAGS) $(AM_CFLAGS)

if HAVE_JOSE
libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
  oidc_helper.h \
  oidc_helper.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/gns/libgnunetgns.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -ljose $(MHD_LIBS) \
	$(LIBGCRYPT_LIBS)
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_openid_connect_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
endif

if HAVE_PABC
libgnunet_plugin_rest_pabc_la_SOURCES = \
  plugin_rest_pabc.c \
  pabc_helper.c
libgnunet_plugin_rest_pabc_la_LIBADD = \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(top_builddir)/src/service/rest/libgnunetrest.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lpabc $(MHD_LIBS)
libgnunet_plugin_rest_pabc_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_pabc_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
endif
