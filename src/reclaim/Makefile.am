# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


REST_PLUGIN = \
  libgnunet_plugin_rest_openid_connect.la \
  libgnunet_plugin_rest_reclaim.la

CREDENTIAL_PLUGIN = \
  libgnunet_plugin_reclaim_credential_jwt.la

if HAVE_PABC
  CREDENTIAL_PLUGIN += libgnunet_plugin_reclaim_credential_pabc.la
  REST_PLUGIN += libgnunet_plugin_rest_pabc.la
endif

EXTRA_DIST = \
  reclaim.conf \
  test_reclaim_defaults.conf \
  test_reclaim.conf \
  $(check_SCRIPTS)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  reclaim.conf

lib_LTLIBRARIES = \
  libgnunetreclaim.la
plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_reclaim.la \
  libgnunet_plugin_reclaim_attribute_basic.la \
  $(CREDENTIAL_PLUGIN) \
  $(REST_PLUGIN)

bin_PROGRAMS = \
 gnunet-reclaim \
 gnunet-did

libexec_PROGRAMS = \
 gnunet-service-reclaim

libgnunet_plugin_rest_reclaim_la_SOURCES = \
  plugin_rest_reclaim.c \
  json_reclaim.h \
  json_reclaim.c
libgnunet_plugin_rest_reclaim_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_reclaim_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_reclaim_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
  oidc_helper.h \
  oidc_helper.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS) \
	$(LIBGCRYPT_LIBS)
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_openid_connect_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)

if HAVE_PABC
libgnunet_plugin_rest_pabc_la_SOURCES = \
  plugin_rest_pabc.c \
  pabc_helper.c
libgnunet_plugin_rest_pabc_la_LIBADD = \
  libgnunetreclaim.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lpabc $(MHD_LIBS)
libgnunet_plugin_rest_pabc_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_pabc_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
endif


libgnunet_plugin_gnsrecord_reclaim_la_SOURCES = \
  plugin_gnsrecord_reclaim.c
libgnunet_plugin_gnsrecord_reclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_reclaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_service_reclaim_SOURCES = \
 gnunet-service-reclaim.c \
 gnunet-service-reclaim_tickets.c \
 gnunet-service-reclaim_tickets.h
gnunet_service_reclaim_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 libgnunetreclaim.la \
 $(top_builddir)/src/gns/libgnunetgns.la \
 $(GN_LIBINTL)

libgnunetreclaim_la_SOURCES = \
 reclaim_api.c \
 reclaim.h \
 reclaim_attribute.c \
 reclaim_attribute.h \
 reclaim_credential.c \
 reclaim_credential.h
libgnunetreclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetreclaim_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


libgnunet_plugin_reclaim_attribute_basic_la_SOURCES = \
  plugin_reclaim_attribute_basic.c
libgnunet_plugin_reclaim_attribute_basic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_basic_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

if HAVE_PABC
libgnunet_plugin_reclaim_credential_pabc_la_SOURCES = \
  plugin_reclaim_credential_pabc.c \
  pabc_helper.c
libgnunet_plugin_reclaim_credential_pabc_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetreclaim.la \
  -ljansson\
  -lpabc \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_credential_pabc_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
endif


libgnunet_plugin_reclaim_credential_jwt_la_SOURCES = \
  plugin_reclaim_credential_jwt.c
libgnunet_plugin_reclaim_credential_jwt_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetreclaim.la \
  -ljansson\
  $(LTLIBINTL)
libgnunet_plugin_reclaim_credential_jwt_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

gnunet_reclaim_SOURCES = \
 gnunet-reclaim.c
gnunet_reclaim_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

test_reclaim_attribute_SOURCES = \
  test_reclaim_attribute.c
test_reclaim_attribute_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetreclaim.la \
  $(GN_LIBINTL)

gnunet_did_SOURCES = \
	gnunet-did.c \
  did_helper.h \
  did_helper.c
gnunet_did_LDADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gns/libgnunetgns.la \
	$(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
	-ljansson


test_w3c_ed25519_2020_SOURCES = \
  test_w3c_ed25519_2020.c
test_w3c_ed25519_2020_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la

check_SCRIPTS = \
  test_reclaim_attribute.sh \
  test_reclaim_issue.sh \
  test_reclaim_consume.sh

check_PROGRAMS = \
  test_reclaim_attribute \
  test_w3c_ed25519_2020

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
