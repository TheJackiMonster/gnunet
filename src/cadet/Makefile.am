# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  cadet.conf

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

libexec_PROGRAMS = \
 gnunet-service-cadet

bin_PROGRAMS = \
 gnunet-cadet

lib_LTLIBRARIES = \
  libgnunetcadet.la

libgnunetcadet_la_SOURCES = \
  cadet_api.c \
  cadet_api_drop_message.c \
  cadet_api_get_channel.c \
  cadet_api_get_path.c \
  cadet_api_list_peers.c \
  cadet_api_list_tunnels.c \
  cadet_api_helper.c
libgnunetcadet_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetcadet_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 7:0:0

gnunet_cadet_SOURCES = \
  gnunet-cadet.c
gnunet_cadet_LDADD = \
  libgnunetcadet.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_cadet_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_service_cadet_SOURCES = \
 gnunet-service-cadet.c gnunet-service-cadet.h \
 gnunet-service-cadet_channel.c gnunet-service-cadet_channel.h \
 gnunet-service-cadet_connection.c gnunet-service-cadet_connection.h \
 gnunet-service-cadet_core.c gnunet-service-cadet_core.h \
 gnunet-service-cadet_dht.c gnunet-service-cadet_dht.h \
 gnunet-service-cadet_hello.c gnunet-service-cadet_hello.h \
 gnunet-service-cadet_tunnels.c gnunet-service-cadet_tunnels.h \
 gnunet-service-cadet_paths.c gnunet-service-cadet_paths.h \
 gnunet-service-cadet_peer.c gnunet-service-cadet_peer.h
gnunet_service_cadet_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la
if LINUX
gnunet_service_cadet_LDFLAGS = -lrt \
    $(GN_LIBINTL)
endif


test_cadet_local_mq_SOURCES = \
  test_cadet_local_mq.c
test_cadet_local_mq_LDADD = \
  libgnunetcadet.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

EXTRA_DIST = \
  cadet.h cadet_protocol.h \
  test_cadet.conf
