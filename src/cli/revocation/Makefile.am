# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

bin_PROGRAMS = \
 gnunet-revocation

gnunet_revocation_SOURCES = \
 gnunet-revocation.c
gnunet_revocation_LDADD = \
  $(top_builddir)/src/service/revocation/libgnunetrevocation.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_revocation_tvg_SOURCES = \
 gnunet-revocation-tvg.c
gnunet_revocation_tvg_LDADD = \
  $(top_builddir)/src/service/revocation/libgnunetrevocation.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

noinst_PROGRAMS = \
 gnunet-revocation-tvg

check_SCRIPTS = \
 #test_local_revocation.py

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = \
 $(check_SCRIPTS) \
 $(check_PROGRAMS)
endif

test_local_revocation.py: test_local_revocation.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_local_revocation.py.in > test_local_revocation.py
	chmod +x test_local_revocation.py

EXTRA_DIST = test_local_revocation.py.in
