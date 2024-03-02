# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  topology.conf


libexec_PROGRAMS = \
 gnunet-daemon-topology

gnunet_daemon_topology_SOURCES = \
 gnunet-daemon-topology.c
gnunet_daemon_topology_LDADD = \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)


#check_PROGRAMS = \
# test_gnunet_daemon_topology

# if ENABLE_TEST_RUN
# AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
# TESTS = $(check_PROGRAMS)
# endif

test_gnunet_daemon_topology_SOURCES = \
 test_gnunet_daemon_topology.c
test_gnunet_daemon_topology_LDADD = \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
 test_gnunet_daemon_topology_data.conf
