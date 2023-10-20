# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  regex.conf

libexec_PROGRAMS = \
  gnunet-service-regex \
  gnunet-daemon-regexprofiler

REGEX_INTERNAL = \
  regex_internal_lib.h \
  regex_internal.h regex_internal.c \
  regex_internal_dht.c
REGEX_INTERNAL_TEST = \
  $(REGEX_INTERNAL) \
  regex_test_lib.c regex_test_lib.h \
  regex_test_graph.c \
  regex_test_random.c

gnunet_service_regex_SOURCES =  \
 $(REGEX_INTERNAL) gnunet-service-regex.c
gnunet_service_regex_LDADD =  -lm \
 $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
 $(top_builddir)/src/service/dht/libgnunetdht.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)

lib_LTLIBRARIES = \
  libgnunetregex.la

libgnunetregex_la_SOURCES = \
  regex_api_announce.c \
  regex_api_search.c \
  regex_ipc.h
libgnunetregex_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunetregex_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS) \
   -version-info 3:1:0


# FIXME we phased out mysql. If we want to keep, needs rewrite
#if HAVE_MYSQL
#noinst_mysql_progs = \
#  gnunet-regex-simulation-profiler

#gnunet_regex_simulation_profiler_SOURCES = \
#  $(REGEX_INTERNAL) gnunet-regex-simulation-profiler.c
#gnunet_regex_simulation_profiler_LDADD = \
#  libgnunetregexblock.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la \
#  $(top_builddir)/src/service/dht/libgnunetdht.la \
#  $(top_builddir)/src/lib/block/libgnunetblock.la \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la
#endif

noinst_PROGRAMS = $(noinst_mysql_progs) \
  perf-regex

perf_regex_SOURCES = \
  $(REGEX_INTERNAL_TEST) perf-regex.c
perf_regex_LDADD = -lm \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la
perf_regex_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_daemon_regexprofiler_SOURCES = \
  $(REGEX_INTERNAL_TEST) gnunet-daemon-regexprofiler.c
gnunet_daemon_regexprofiler_LDADD = -lm \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_daemon_regexprofiler_LDFLAGS = \
  $(GN_LIBINTL)

check_PROGRAMS = \
  test_regex_integration \
  test_regex_eval_api \
  test_regex_iterate_api \
  test_regex_proofs \
  test_regex_graph_api \
  test_regex_api

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_PROGRAMS)
endif

test_regex_eval_api_SOURCES = \
  $(REGEX_INTERNAL_TEST) test_regex_eval_api.c
test_regex_eval_api_LDADD = -lm \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_regex_integration_SOURCES = \
  test_regex_integration.c
test_regex_integration_LDADD = -lm \
  libgnunetregex.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_regex_api_SOURCES = \
  test_regex_api.c
test_regex_api_LDADD = -lm \
  libgnunetregex.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_regex_iterate_api_SOURCES = \
  $(REGEX_INTERNAL) test_regex_iterate_api.c
test_regex_iterate_api_LDADD = -lm \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_regex_proofs_SOURCES = \
  $(REGEX_INTERNAL_TEST) test_regex_proofs.c
test_regex_proofs_LDADD = -lm \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_regex_graph_api_SOURCES = \
  $(REGEX_INTERNAL_TEST) test_regex_graph_api.c
test_regex_graph_api_LDADD = -lm \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/plugin/regex/libgnunetregexblock.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


EXTRA_DIST = \
  regex_simulation_profiler_test.conf \
  test_regex_api_data.conf
