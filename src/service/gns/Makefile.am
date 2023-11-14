# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_GLIBCNSS
NSS_SUBDIR = nss
endif

SUBDIRS = . $(NSS_SUBDIR)

if HAVE_LIBIDN
  LIBIDN= -lidn
else
  LIBIDN=
endif

if HAVE_LIBIDN2
  LIBIDN2= -lidn2
else
  LIBIDN2=
endif

USE_VPN = $(top_builddir)/src/service/vpn/libgnunetvpn.la

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  gns.conf
dist_pkgcfg_DATA = \
  tlds.conf

lib_LTLIBRARIES = \
  libgnunetgns.la

libexec_PROGRAMS = \
  gnunet-service-gns \
  gnunet-dns2gns

noinst_PROGRAMS = \
  gnunet-gns-benchmark

if HAVE_PDFLATEX
libexec_PROGRAMS += gnunet-bcd
endif

if HAVE_GNUTLS
libexec_PROGRAMS += gnunet-gns-proxy
endif

gnunet_gns_benchmark_SOURCES = \
 gnunet-gns-benchmark.c
gnunet_gns_benchmark_LDADD = \
  libgnunetgns.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_bcd_SOURCES = \
 gnunet-bcd.c
gnunet_bcd_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL) $(MHD_LIBS)
gnunet_bcd_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


gnunet_dns2gns_SOURCES = \
 gnunet-dns2gns.c
gnunet_dns2gns_LDADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  libgnunetgns.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(USE_VPN) \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

if HAVE_SUDO
SUDO_OR_DOAS_BINARY= $(SUDO_BINARY) -n
else
if HAVE_DOAS_BINARY
SUDO_OR_DOAS_BINARY= $(DOAS_BINARY)
endif
endif

if LINUX
HIJACKBIN = gnunet-dns2gns
install-exec-hook:
	$(SUDO_OR_DOAS_BINARY) setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(libexecdir)/gnunet-dns2gns || true
else
install-exec-hook:
endif

gnunet_gns_proxy_SOURCES = \
 gnunet-gns-proxy.c
gnunet_gns_proxy_LDADD = $(MHD_LIBS) @LIBCURL@ -lgnutls \
  libgnunetgns.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
if HAVE_GNUTLS_DANE
gnunet_gns_proxy_LDADD += -lgnutls-dane
endif
gnunet_gns_proxy_CFLAGS = $(MHD_CFLAGS) @LIBCURL_CPPFLAGS@ $(AM_CFLAGS)

test_gns_proxy_SOURCES = \
  test_gns_proxy.c
test_gns_proxy_LDADD = $(MHD_LIBS) @LIBCURL@ -lgnutls \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
test_gns_proxy_CFLAGS = $(MHD_CFLAGS) @LIBCURL_CPPFLAGS@ $(AM_CFLAGS)

#gnunet_gns_import_SOURCES = \
#  gnunet-gns-import.c
#gnunet_gns_import_LDADD = \
#  $(top_builddir)/src/service/identity/libgnunetidentity.la \
#  $(top_builddir)/src/service/namestore/libgnunetnamestore.la \
#  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la \
#  $(GN_LIBINTL)


gnunet_service_gns_SOURCES = \
 gnunet-service-gns.c gnunet-service-gns.h \
 gnunet-service-gns_resolver.c gnunet-service-gns_resolver.h \
 gnunet-service-gns_interceptor.c gnunet-service-gns_interceptor.h
gnunet_service_gns_LDADD = \
  -lm \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/revocation/libgnunetrevocation.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/dns/libgnunetdns.la \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/service/namecache/libgnunetnamecache.la \
  $(LIBIDN) $(LIBIDN2) \
  $(GN_LIBINTL)


libgnunetgns_la_SOURCES = \
 gns_api.c gns_api.h \
 gns_tld_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIB) \
 $(top_builddir)/src/service/identity/libgnunetidentity.la \
 $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la
libgnunetgns_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS)


if HAVE_GNUTLS
check_PROGRAMS = \
  test_gns_proxy
endif

if HAVE_GNUTLS_CURL
check_SCRIPTS = \
  test_proxy.sh
endif

EXTRA_DIST = \
  test_gns_proxy.conf \
  test_proxy.sh

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
