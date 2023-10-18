# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexec_PROGRAMS = \
 gnunet-service-resolver

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

gnunet_service_resolver_SOURCES = \
 gnunet-service-resolver.c
gnunet_service_resolver_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
if HAVE_GETADDRINFO_A
gnunet_service_resolver_LDADD += -lanl
endif


check_PROGRAMS = \
 test_resolver_api.nc

# Declare .nc (NO-CONCURRENCY) as a test extension so that we can impart
# sequential execution order for them
TEST_EXTENSIONS = .nc
test_test_client_unix.log: test_client.log

test_resolver_api_nc_SOURCES = \
 test_resolver_api.c
test_resolver_api_nc_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_resolver_api_data.conf
