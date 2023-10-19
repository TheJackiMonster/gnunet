# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   rest.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetrest.la 

libexec_PROGRAMS = \
  gnunet-rest-server

EXTRA_DIST = \
 rest.conf

gnunet_rest_server_SOURCES = \
 gnunet-rest-server.c \
 config_plugin.c \
 copying_plugin.c \
 identity_plugin.c \
 namestore_plugin.c \
 gns_plugin.c \
 openid_plugin.c \
 oidc_helper.c \
 reclaim_plugin.c json_reclaim.c
gnunet_rest_server_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/json/libgnunetjson.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecordjson.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/service/gns/libgnunetgns.la \
  $(top_builddir)/src/service/reclaim/libgnunetreclaim.la \
  libgnunetrest.la \
	-ljose \
	$(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL) $(MHD_LIBS)
gnunet_rest_server_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)

libgnunetrest_la_SOURCES = \
  rest.c
libgnunetrest_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIB) \
  $(GN_LIBINTL) $(MHD_LIBS)
libgnunetrest_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0
libgnunetrest_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
