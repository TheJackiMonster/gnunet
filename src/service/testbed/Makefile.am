# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

lib_LTLIBRARIES = \
  libgnunettestbed.la \
  libgnunettestingtestbed.la

libgnunettestbed_la_SOURCES = \
  testbed.c
libgnunettestbed_la_LIBADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la

libgnunettestingtestbed_la_SOURCES = \
  testbed_api_cmd_system_create.c \
  testing_testbed_traits.c
libgnunettestingtestbed_la_LIBADD = \
  libgnunettestbed.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


bin_PROGRAMS = \
 gnunet-testbed

gnunet_testbed_SOURCES = \
 gnunet-testbed.c
gnunet_testbed_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(GN_LIBINTL)

check_PROGRAMS = \
 test_testbed_portreservation

if ENABLE_TEST_RUN_TESTBED
  AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = \
#  test_testbed_portreservation
endif

test_testbed_portreservation_SOURCES = \
 test_testbed_portreservation.c
test_testbed_portreservation_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la
