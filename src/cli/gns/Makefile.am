# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgdata_DATA = \
  gnunet-gns-proxy-ca.template

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

bin_PROGRAMS = \
  gnunet-gns

bin_SCRIPTS = \
  gnunet-gns-proxy-setup-ca

gnunet-gns-proxy-setup-ca: gnunet-gns-proxy-setup-ca.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet-gns-proxy-setup-ca.in > gnunet-gns-proxy-setup-ca
	@chmod +x gnunet-gns-proxy-setup-ca

test_gnunet_gns.sh: test_gnunet_gns.sh.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_gnunet_gns.sh.in > test_gnunet_gns.sh
	@chmod +x test_gnunet_gns.sh

CLEANFILES = test_gnunet_gns.sh

gnunet_gns_SOURCES = \
 gnunet-gns.c
gnunet_gns_LDADD = \
  $(top_builddir)/src/service/gns/libgnunetgns.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBIDN) $(LIBIDN2) \
  $(GN_LIBINTL)

check_SCRIPTS = \
   test_gns_lookup.sh \
   test_gns_config_lookup.sh \
   test_gns_ipv6_lookup.sh\
   test_gns_txt_lookup.sh\
   test_gns_caa_lookup.sh\
   test_gns_mx_lookup.sh \
   test_gns_gns2dns_lookup.sh \
   test_gns_gns2dns_zkey_lookup.sh \
   test_gns_gns2dns_cname_lookup.sh \
   test_gns_dht_lookup.sh\
   test_gns_delegated_lookup.sh \
   test_gns_at_lookup.sh\
   test_gns_zkey_lookup.sh\
   test_gns_rel_expiration.sh\
   test_gns_soa_lookup.sh\
   test_gns_revocation.sh\
   test_gns_redirect_lookup.sh

EXTRA_DIST = \
  test_gns_defaults.conf \
  test_gns_lookup.conf \
  test_gns_proxy.conf \
  test_gns_simple_lookup.conf \
  openssl.cnf \
  gnunet-gns-proxy-setup-ca.in \
  zonefiles/J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey \
  zonefiles/OEFL7A4VEF1B40QLEMTG5D8G1CN6EN16QUSG5R2DT71GRJN34LSG.zkey \
  zonefiles/test_zonekey \
  test_gns_lookup.sh \
  test_gns_config_lookup.sh \
  test_gns_ipv6_lookup.sh\
  test_gns_txt_lookup.sh\
  test_gns_caa_lookup.sh\
  test_gns_mx_lookup.sh \
  test_gns_gns2dns_lookup.sh \
  test_gns_gns2dns_zkey_lookup.sh \
  test_gns_gns2dns_cname_lookup.sh \
  test_gns_dht_lookup.sh\
  test_gns_delegated_lookup.sh \
  test_gns_at_lookup.sh\
  test_gns_zkey_lookup.sh\
  test_gns_rel_expiration.sh\
  test_gns_soa_lookup.sh\
  test_gns_revocation.sh\
  test_gns_redirect_lookup.sh\
  test_proxy.sh\
	$(pkgdata_DATA) \
  test_gnunet_gns.sh.in

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
