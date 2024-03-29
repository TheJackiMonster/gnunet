# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  statistics.conf

lib_LTLIBRARIES = libgnunetstatistics.la

libgnunetstatistics_la_SOURCES = \
  statistics_api.c statistics.h
libgnunetstatistics_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetstatistics_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 2:0:0

libexec_PROGRAMS = \
 gnunet-service-statistics

gnunet_service_statistics_SOURCES = \
 gnunet-service-statistics.c
gnunet_service_statistics_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
 test_statistics_api \
 test_statistics_api_loop \
 test_statistics_api_watch \
 test_statistics_api_watch_zero_value

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

test_statistics_api_SOURCES = \
 test_statistics_api.c
test_statistics_api_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_statistics_api_loop_SOURCES = \
 test_statistics_api_loop.c
test_statistics_api_loop_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_statistics_api_watch_SOURCES = \
 test_statistics_api_watch.c
test_statistics_api_watch_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_statistics_api_watch_zero_value_SOURCES = \
 test_statistics_api_watch_zero_value.c
test_statistics_api_watch_zero_value_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

# Needs to be done with CLI
#if HAVE_PYTHON
#check_SCRIPTS = \
#  test_gnunet_statistics.py
#endif
#
#SUFFIXES = .py.in .py
#.py.in.py:
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $(srcdir)/$< > $@
#	chmod +x $@
#
#test_gnunet_statistics.py: test_gnunet_statistics.py.in Makefile
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $(srcdir)/test_gnunet_statistics.py.in > test_gnunet_statistics.py
#	chmod +x test_gnunet_statistics.py
#
EXTRA_DIST = \
  test_statistics_api_data.conf
