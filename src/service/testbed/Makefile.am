# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  testbed.conf

lib_LTLIBRARIES = \
  libgnunettestbed.la

libgnunettestbed_la_SOURCES = \
  testbed_lib.h \
  testbed.c \
  testbed_api_cmd_system_create.c \
  testbed_api_cmd_system_destroy.c
libgnunettestbed_la_LIBADD = \
 $(top_builddir)/src/service/arm/libgnunetarm.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la

bin_PROGRAMS = \
 gnunet-testbed

#libexec_PROGRAMS = \
# test_testbed_start_with_config

noinst_PROGRAMS = \
 list-keys

#testbed_api_cmd_system_create_SOURCES = \
# testbed_api_cmd_system_create.c
#testbed_api_cmd_system_create_LDADD = \
# libgnunettestbed.la \
# $(top_builddir)/src/lib/util/libgnunetutil.la \
# $(top_builddir)/src/lib/testing/libgnunettesting.la


#testbed_SOURCES = \
# testbed.c
#testbed_LDADD = \
# libgnunettestbed.la \
# $(top_builddir)/src/lib/util/libgnunetutil.la \
# $(top_builddir)/src/lib/testing/libgnunettesting.la \
# $(GN_LIBINTL)

gnunet_testbed_SOURCES = \
 gnunet-testbed.c
gnunet_testbed_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(GN_LIBINTL)

list_keys_SOURCES = \
 list-keys.c
list_keys_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)


check_PROGRAMS = \
 test_testbed_portreservation \
 test_testbed_servicestartup \
 test_testbed_peerstartup \
 test_testbed_peerstartup2 \
 test_testbed_sharedservices

# if ENABLE_TEST_RUN_TESTBED
# AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = \
#  test_testbed_portreservation \
#  test_testbed_peerstartup \
#  test_testbed_peerstartup2 \
#  test_testbed_servicestartup
# endif

#test_testbed_start_with_config_SOURCES = \
# test_testbed_start_with_config.c
#test_testbed_start_with_config_LDADD = \
# libgnunettestbed.la \
# $(top_builddir)/src/lib/util/libgnunetutil.la \
# $(top_builddir)/src/lib/hello/libgnunethello.la

test_testbed_portreservation_SOURCES = \
 test_testbed_portreservation.c
test_testbed_portreservation_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testbed_peerstartup_SOURCES = \
 test_testbed_peerstartup.c
test_testbed_peerstartup_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testbed_peerstartup2_SOURCES = \
 test_testbed_peerstartup2.c
test_testbed_peerstartup2_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testbed_servicestartup_SOURCES = \
 test_testbed_servicestartup.c
test_testbed_servicestartup_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testbed_sharedservices_SOURCES = \
 test_testbed_sharedservices.c
test_testbed_sharedservices_LDADD = \
 libgnunettestbed.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_testbed_defaults.conf \
  test_testbed_sharedservices.conf \
  testbed_lib.h
