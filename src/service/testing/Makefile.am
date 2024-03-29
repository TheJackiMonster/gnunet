# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  testing.conf

libexec_PROGRAMS = \
 test_testing_start_with_config \
  gnunet-cmds-helper

plugindir = $(libdir)/gnunet

lib_LTLIBRARIES = \
  libgnunettesting.la

gnunet_cmds_helper_SOURCES = \
  gnunet-cmds-helper.c
gnunet_cmds_helper_LDADD = $(XLIB) \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 libgnunettesting.la \
 $(LTLIBINTL) $(Z_LIBS)

libgnunettesting_la_SOURCES = \
  testing_api_cmd_exec_bash_script.c \
  testing_api_cmd_barrier.c \
  testing_api_cmd_barrier_reached.c \
  testing_api_cmd_finish.c \
  testing_api_cmd_local_test_prepared.c \
  testing_api_cmd_send_peer_ready.c \
  testing_api_cmd_block_until_external_trigger.c \
  testing_api_cmd_netjail_start.c \
  testing_api_cmd_netjail_start_cmds_helper.c \
  testing_api_cmd_netjail_stop_cmds_helper.c \
  testing_api_cmd_netjail_stop.c \
  testing.c testing.h \
  testing_api_cmd_system_create.c \
  testing_api_cmd_system_destroy.c \
  testing_api_cmd_batch.c \
  testing_api_loop.c \
  testing_api_traits.c
libgnunettesting_la_LIBADD = \
 $(top_builddir)/src/service/arm/libgnunetarm.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettesting_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 2:0:1

bin_PROGRAMS = \
 gnunet-testing

noinst_PROGRAMS = \
 list-keys

gnunet_testing_SOURCES = \
 gnunet-testing.c
gnunet_testing_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)

list_keys_SOURCES = \
 list-keys.c
list_keys_LDADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)


check_PROGRAMS = \
 test_testing_portreservation \
 test_testing_servicestartup \
 test_testing_peerstartup \
 test_testing_peerstartup2 \
 test_testing_sharedservices

# if ENABLE_TEST_RUN_TESTING
# AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = \
#  test_testing_portreservation \
#  test_testing_peerstartup \
#  test_testing_peerstartup2 \
#  test_testing_servicestartup
# endif

test_testing_start_with_config_SOURCES = \
 test_testing_start_with_config.c
test_testing_start_with_config_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/lib/hello/libgnunethello.la

test_testing_portreservation_SOURCES = \
 test_testing_portreservation.c
test_testing_portreservation_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testing_peerstartup_SOURCES = \
 test_testing_peerstartup.c
test_testing_peerstartup_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testing_peerstartup2_SOURCES = \
 test_testing_peerstartup2.c
test_testing_peerstartup2_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testing_servicestartup_SOURCES = \
 test_testing_servicestartup.c
test_testing_servicestartup_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

test_testing_sharedservices_SOURCES = \
 test_testing_sharedservices.c
test_testing_sharedservices_LDADD = \
 libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_testing_defaults.conf \
  test_testing_sharedservices.conf \
  testing_cmds.h
