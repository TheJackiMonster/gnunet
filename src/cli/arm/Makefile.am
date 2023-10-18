# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-arm

gnunet_arm_SOURCES = \
 gnunet-arm.c
gnunet_arm_LDADD = \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

# FIXME the respective conf file now resides in service/arm/
#if HAVE_PYTHON
#check_SCRIPTS = \
# test_gnunet_arm.py
#endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

#SUFFIXES = .py.in .py
#.py.in.py:
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/$< > $@
#	chmod +x $@
#
#test_gnunet_arm.py: test_gnunet_arm.py.in Makefile
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_gnunet_arm.py.in > test_gnunet_arm.py
#	chmod +x test_gnunet_arm.py
#
#EXTRA_DIST = \
#  test_arm_api_data.conf \
#  test_gnunet_arm.py.in
