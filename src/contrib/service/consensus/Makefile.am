# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  consensus.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif


libexec_PROGRAMS = \
 gnunet-service-consensus

if ENABLE_MALICIOUS
libexec_PROGRAMS += \
 gnunet-service-evil-consensus
endif

SUFFIXES = .py.in .py

.py.in.py:
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $< > $@
	chmod +x $@

check-python-style:
	flake8 consensus-simulation.py.in

lib_LTLIBRARIES = \
  libgnunetconsensus.la

gnunet_service_consensus_SOURCES = \
 gnunet-service-consensus.c
gnunet_service_consensus_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/contrib/service/set/libgnunetset.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)

gnunet_service_evil_consensus_SOURCES = \
 gnunet-service-consensus.c \
 consensus_protocol.h
gnunet_service_evil_consensus_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/contrib/service/set/libgnunetset.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)
gnunet_service_evil_consensus_CFLAGS = -DEVIL

libgnunetconsensus_la_SOURCES = \
  consensus_api.c \
  consensus.h
libgnunetconsensus_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetconsensus_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_consensus.la

libgnunet_plugin_block_consensus_la_SOURCES = \
  plugin_block_consensus.c
libgnunet_plugin_block_consensus_la_LIBADD = \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_consensus_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



#check_PROGRAMS = \
# test_consensus_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_consensus_api_SOURCES = \
 test_consensus_api.c
test_consensus_api_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  libgnunetconsensus.la

noinst_SCRIPTS = \
	consensus-simulation.py

CLEANFILES = \
	$(noinst_SCRIPTS)

EXTRA_DIST = \
  test_consensus.conf \
  consensus-simulation.py.in
