# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  transport.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

noinst_PROGRAMS = \
 gnunet-communicator-udp

TESTING_LIBS = \
  libgnunettestingtransport.la

lib_LTLIBRARIES = \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  libgnunettransportcommunicator.la \
  libgnunettransportmonitor.la \
  $(TESTING_LIBS)

libgnunettestingtransport_la_SOURCES = \
  testing_transport_traits.c transport-testing-cmds.h \
  transport-testing-communicator.c transport-testing-communicator.h 
#  transport_api_cmd_connecting_peers.c \
#  transport_api_cmd_backchannel_check.c \
#  transport_api_cmd_send_simple.c \
#  transport_api_cmd_send_simple_performance.c \
#  transport-testing2.c transport-testing2.h \
#  transport-testing-cmds.h \
#  transport-testing-filenames2.c \
#  transport-testing-loggers2.c \
#  transport-testing-main2.c \
#  transport-testing-send2.c 
libgnunettestingtransport_la_LIBADD = \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/service/testbed/libgnunettestbed.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunettestingtransport_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunettransportapplication_la_SOURCES = \
  transport_api2_application.c
libgnunettransportapplication_la_LIBADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettransportapplication_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libgnunettransportcore_la_SOURCES = \
  transport_api2_core.c
libgnunettransportcore_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

libgnunettransportcommunicator_la_SOURCES = \
  transport_api2_communication.c
libgnunettransportcommunicator_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportcommunicator_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libgnunettransportmonitor_la_SOURCES = \
  transport_api2_monitor.c
libgnunettransportmonitor_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportmonitor_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-transport \
 gnunet-communicator-unix \
 gnunet-communicator-udp \
 gnunet-communicator-tcp \
 gnunet-communicator-http3
if HAVE_EXPERIMENTAL
if HAVE_QUICHE
libexec_PROGRAMS += \
 gnunet-communicator-quic
endif
endif


#bin_PROGRAMS = \
# gnunet-transport

bin_SCRIPTS = \
 gnunet-transport-certificate-creation

# See: https://www.gnu.org/software/automake/manual/html_node/Scripts.html#Scripts
do_subst = sed -e 's,[@]pkgdatadir[@],$(pkgdatadir),g'


gnunet-transport-certificate-creation: gnunet-transport-certificate-creation.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $(srcdir)/gnunet-transport-certificate-creation.in > gnunet-transport-certificate-creation
	@chmod +x gnunet-transport-certificate-creation




gnunet_communicator_unix_SOURCES = \
 gnunet-communicator-unix.c
gnunet_communicator_unix_LDADD = \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

gnunet_communicator_tcp_SOURCES = \
 gnunet-communicator-tcp.c
gnunet_communicator_tcp_LDADD = \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS)

gnunet_communicator_udp_SOURCES = \
 gnunet-communicator-udp.c
gnunet_communicator_udp_LDADD = \
  libgnunettransportapplication.la \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS)

if HAVE_EXPERIMENTAL
if HAVE_QUICHE
gnunet_communicator_quic_SOURCES = \
  gnunet-communicator-quic.c
gnunet_communicator_quic_LDADD = \
  libgnunettransportapplication.la \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lquiche \
  $(LIBGCRYPT_LIBS)
endif
endif

gnunet_communicator_http3_SOURCES = \
 gnunet-communicator-http3.c
gnunet_communicator_http3_LDADD = \
  libgnunettransportapplication.la \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lngtcp2 \
  -lgnutls \
  -lngtcp2_crypto_gnutls \
  -lnghttp3 \
  $(LIBGCRYPT_LIBS)

#gnunet_transport_SOURCES = \
# gnunet-transport.c
#gnunet_transport_LDADD = \
#  libgnunettransport.la \
#  $(top_builddir)/src/lib/hello/libgnunethello.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la \
#  $(GN_LIBINTL)

gnunet_service_transport_SOURCES = \
 gnunet-service-transport.c transport.h
gnunet_service_transport_LDADD = \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL)

#plugin_LTLIBRARIES = \
#  libgnunet_test_transport_plugin_cmd_simple_send_performance.la \
#  libgnunet_test_transport_plugin_cmd_nat_upnp.la \
#  libgnunet_test_transport_plugin_cmd_simple_send.la \
#  libgnunet_test_transport_plugin_cmd_simple_send_broadcast.la \
#  libgnunet_test_transport_plugin_cmd_simple_send_dv.la \
#  libgnunet_test_transport_plugin_cmd_udp_backchannel.la

libgnunet_test_transport_plugin_cmd_nat_upnp_la_SOURCES = \
 test_transport_plugin_cmd_nat_upnp.c
libgnunet_test_transport_plugin_cmd_nat_upnp_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_nat_upnp_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_test_transport_plugin_cmd_udp_backchannel_la_SOURCES = \
 test_transport_plugin_cmd_udp_backchannel.c
libgnunet_test_transport_plugin_cmd_udp_backchannel_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_udp_backchannel_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_test_transport_plugin_cmd_simple_send_la_SOURCES = \
 test_transport_plugin_cmd_simple_send.c
libgnunet_test_transport_plugin_cmd_simple_send_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_simple_send_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_test_transport_plugin_cmd_simple_send_performance_la_SOURCES = \
 test_transport_plugin_cmd_simple_send_performance.c
libgnunet_test_transport_plugin_cmd_simple_send_performance_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_simple_send_performance_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_test_transport_plugin_cmd_simple_send_broadcast_la_SOURCES = \
 test_transport_plugin_cmd_simple_send_broadcast.c
libgnunet_test_transport_plugin_cmd_simple_send_broadcast_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_simple_send_broadcast_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_test_transport_plugin_cmd_simple_send_dv_la_SOURCES = \
 test_transport_plugin_cmd_simple_send_dv.c
libgnunet_test_transport_plugin_cmd_simple_send_dv_la_LIBADD = \
  libgnunettestingtransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  $(top_builddir)/src/lib/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_transport_plugin_cmd_simple_send_dv_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
 test_communicator_basic-http3 \
 test_communicator_basic-tcp \
 test_communicator_basic-udp \
 test_communicator_rekey-tcp \
 test_communicator_bidirect-tcp \
 test_communicator_rekey-udp \
 test_communicator_backchannel-udp

if HAVE_EXPERIMENTAL
check_PROGRAMS += test_communicator_basic-quic \
 test_communicator_basic-unix
# check_SCRIPTS= \
  # test_transport_start_testcase.sh \
  # test_transport_simple_send_performance.sh \
  # test_transport_nat_icmp_tcp.sh \
  # test_transport_nat_upnp.sh \
  # test_transport_simple_send_string.sh \
  # test_transport_simple_send.sh \
  # test_transport_simple_send_broadcast.sh \
  # test_transport_udp_backchannel.sh \
  # test_transport_simple_send_dv_circle.sh \
  # test_transport_simple_send_dv_inverse.sh
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_SCRIPTS) \
  $(check_PROGRAMS)
endif



test_communicator_basic_unix_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_unix_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_basic_tcp_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_tcp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_basic_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_udp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_basic_quic_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_quic_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_basic_http3_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_http3_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_rekey_tcp_SOURCES = \
 test_communicator_basic.c
test_communicator_rekey_tcp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_rekey_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_rekey_udp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_backchannel_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_backchannel_udp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_communicator_bidirect_tcp_SOURCES = \
 test_communicator_basic.c
test_communicator_bidirect_tcp_LDADD = \
 libgnunettestingtransport.la \
 $(top_builddir)/src/lib/testing/libgnunettesting.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(top_builddir)/src/service/statistics/libgnunetstatistics.la

test_transport_api2_tcp_SOURCES = \
 test_transport_api2.c
test_transport_api2_tcp_LDADD = \
 $(top_builddir)/src/lib/hello/libgnunethello.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la  \
 libgnunettestingtransport.la

EXTRA_DIST = \
test_transport_start_testcase.sh \
test_transport_simple_send_performance.sh \
test_transport_nat_icmp_tcp.sh \
test_transport_nat_upnp.sh \
test_transport_simple_send_string.sh \
test_transport_simple_send.sh \
test_transport_simple_send_broadcast.sh \
test_transport_udp_backchannel.sh \
test_transport_simple_send_dv_circle.sh \
test_transport_simple_send_dv_inverse.sh \
gnunet-transport-certificate-creation.in \
test_plugin_hostkey \
test_plugin_hostkey.ecc \
test_delay \
template_cfg_peer1.conf\
template_cfg_peer2.conf\
test_transport_api_data.conf\
test_transport_api_multi_peer1.conf\
test_transport_api_multi_peer2.conf\
test_transport_api_tcp_nat_peer1.conf\
test_transport_api_tcp_nat_peer2.conf\
test_transport_api_tcp_peer1.conf\
test_transport_api_tcp_peer2.conf\
test_transport_api2_tcp_peer1.conf\
test_transport_api2_tcp_peer2.conf\
test_transport_api_udp_nat_peer1.conf\
test_transport_api_udp_nat_peer2.conf\
test_transport_api_udp_peer1.conf\
test_transport_api_udp_peer2.conf\
test_transport_api_unix_peer1.conf\
test_transport_api_unix_peer2.conf\
test_transport_api_monitor_peers_peer1.conf\
test_transport_api_monitor_peers_peer2.conf\
test_transport_api_monitor_validation_peer1.conf\
test_transport_api_monitor_validation_peer2.conf\
test_transport_defaults.conf\
test_communicator_unix_basic_peer1.conf \
test_communicator_unix_basic_peer2.conf \
test_communicator_tcp_basic_peer1.conf \
test_communicator_tcp_basic_peer2.conf \
test_communicator_udp_basic_peer1.conf \
test_communicator_http3_basic_peer1.conf \
test_communicator_http3_basic_peer2.conf \
test_communicator_udp_basic_peer2.conf \
test_communicator_tcp_rekey_peer1.conf \
test_communicator_tcp_rekey_peer2.conf \
test_communicator_udp_rekey_peer1.conf \
test_communicator_udp_rekey_peer2.conf \
test_communicator_udp_backchannel_peer1.conf \
test_communicator_udp_backchannel_peer2.conf \
test_communicator_tcp_bidirect_peer1.conf \
test_communicator_tcp_bidirect_peer2.conf
