# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

 HOSTLIST_SERVER_SOURCES = \
   gnunet-daemon-hostlist_server.c gnunet-daemon-hostlist_server.h
 GN_LIBMHD = $(MHD_LIBS)
 GN_CPPMHD = $(MHD_CFLAGS)

libexec_PROGRAMS = \
 gnunet-daemon-hostlist
dist_pkgcfg_DATA = \
  hostlist.conf

gnunet_daemon_hostlist_SOURCES = \
 gnunet-daemon-hostlist.c gnunet-daemon-hostlist.h \
 gnunet-daemon-hostlist_client.c gnunet-daemon-hostlist_client.h \
 $(HOSTLIST_SERVER_SOURCES)

gnunet_daemon_hostlist_LDADD = \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBMHD) \
  -ljansson \
  @LIBCURL@ \
  $(GN_LIBINTL)

gnunet_daemon_hostlist_CFLAGS = \
  $(GN_CPPMHD) \
  @LIBCURL_CPPFLAGS@ \
  $(AM_CFLAGS)

#check_PROGRAMS = \
# test_gnunet_daemon_hostlist \
# test_gnunet_daemon_hostlist_reconnect \
# test_gnunet_daemon_hostlist_learning

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 $(check_PROGRAMS)
endif

#test_gnunet_daemon_hostlist_SOURCES = \
# test_gnunet_daemon_hostlist.c
#test_gnunet_daemon_hostlist_LDADD = \
#  $(top_builddir)/src/service/transport/libgnunettransport.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#test_gnunet_daemon_hostlist_reconnect_SOURCES = \
# test_gnunet_daemon_hostlist_reconnect.c
#test_gnunet_daemon_hostlist_reconnect_LDADD = \
#  $(top_builddir)/src/service/transport/libgnunettransport.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la
#
#test_gnunet_daemon_hostlist_learning_SOURCES = \
# test_gnunet_daemon_hostlist_learning.c
#test_gnunet_daemon_hostlist_learning_LDADD = \
#  $(top_builddir)/src/service/transport/libgnunettransport.la \
#  $(top_builddir)/src/service/core/libgnunetcore.la \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_hostlist_defaults.conf \
  test_gnunet_daemon_hostlist_data.conf \
  test_gnunet_daemon_hostlist_peer1.conf \
  test_gnunet_daemon_hostlist_peer2.conf \
  test_learning_adv_peer.conf \
  test_learning_learn_peer.conf \
  test_learning_learn_peer2.conf \
  learning_data.conf
