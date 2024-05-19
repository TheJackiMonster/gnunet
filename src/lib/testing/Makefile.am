# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

libexec_PROGRAMS = \
  gnunet-cmds-helper

plugindir = $(libdir)/gnunet

lib_LTLIBRARIES = \
  libgnunettesting.la

gnunet_cmds_helper_SOURCES = \
  gnunet-cmds-helper.c
gnunet_cmds_helper_LDADD = $(XLIB) \
  libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)

libgnunettesting_la_SOURCES = \
  testing_api_barrier.c testing_api_barrier.h \
  testing_api_cmd_barrier_create.c \
  testing_api_cmd_barrier_reached.c \
  testing_api_cmd_batch.c testing_api_cmd_batch.h \
  testing_api_cmd_exec.c \
  testing_api_cmd_finish.c \
  testing_api_cmd_get_topo.c \
  testing_api_cmd_netjail_start.c \
  testing_api_cmd_netjail_start_cmds_helper.c \
  testing_api_cmd_signal.c \
  testing_api_cmd_stat.c \
  testing_api_cmds.c \
  testing_api_loop.c testing_api_loop.h \
  testing_api_main.c \
  testing_api_traits.c \
  testing_api_topology.c testing_api_topology.h
libgnunettesting_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunettesting_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 3:0:0

AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;


bin_PROGRAMS = \
  gnunet-testing-netjail-launcher

gnunet_testing_netjail_launcher_SOURCES = \
  gnunet-testing-netjail-launcher.c
gnunet_testing_netjail_launcher_LDADD = $(XLIB) \
  libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)

check_PROGRAMS = \
  test_testing_api

check_SCRIPTS = \
  test_netjail_api.sh

TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)

test_testing_api_SOURCES = \
  test_testing_api.c
test_testing_api_LDADD = \
  libgnunettesting.la \
  -lgnunetutil \
  $(XLIB)

EXTRA_DIST = \
  test_netjail_topo.conf
