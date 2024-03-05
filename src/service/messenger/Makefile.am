# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  messenger.conf

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

libexec_PROGRAMS = \
 gnunet-service-messenger \
 $(EXP_LIBEXEC)

plugin_LTLIBRARIES = \
  libgnunet_test_messenger_plugin_cmd_simple_join.la

TESTING_LIBS = \
  libgnunetmessengertesting.la

lib_LTLIBRARIES = \
  libgnunetmessenger.la \
  $(EXP_LIB) \
  $(TESTING_LIBS)

libgnunetmessenger_la_SOURCES = \
  messenger_api.c \
  messenger_api_contact.c messenger_api_contact.h \
  messenger_api_contact_store.c messenger_api_contact_store.h \
  messenger_api_message.c messenger_api_message.h \
  messenger_api_message_control.c messenger_api_message_control.h \
  messenger_api_message_kind.c messenger_api_message_kind.h \
  messenger_api_list_tunnels.c messenger_api_list_tunnels.h \
  messenger_api_queue_messages.c messenger_api_queue_messages.h \
  messenger_api_util.c messenger_api_util.h \
  messenger_api_handle.c messenger_api_handle.h \
  messenger_api_room.c messenger_api_room.h
libgnunetmessenger_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetmessenger_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

libgnunetmessengertesting_la_SOURCES = \
  messenger_api_cmd_join_room.c \
  messenger_api_cmd_start_service.c \
  messenger_api_cmd_stop_service.c \
  messenger_api_traits.c \
  messenger-testing.c messenger-testing.h
libgnunetmessengertesting_la_LIBADD = \
  libgnunetmessenger.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/transport/libgnunettransporttesting2.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunetmessengertesting_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunet_test_messenger_plugin_cmd_simple_join_la_SOURCES = \
  messenger-testing-cmds.h \
  test_messenger_plugin_cmd_simple_join.c
libgnunet_test_messenger_plugin_cmd_simple_join_la_LIBADD = \
  libgnunetmessenger.la \
  libgnunetmessengertesting.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(top_builddir)/src/service/core/libgnunetcoretesting.la \
  $(top_builddir)/src/service/transport/libgnunettransporttesting2.la \
  $(top_builddir)/src/service/transport/libgnunettransportapplication.la \
  $(top_builddir)/src/service/transport/libgnunettransportcore.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/arm/libgnunetarm.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_test_messenger_plugin_cmd_simple_join_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

gnunet_service_messenger_SOURCES = \
  gnunet-service-messenger.c gnunet-service-messenger.h \
  gnunet-service-messenger_service.c gnunet-service-messenger_service.h \
  gnunet-service-messenger_list_handles.c gnunet-service-messenger_list_handles.h \
  gnunet-service-messenger_list_messages.c gnunet-service-messenger_list_messages.h \
  gnunet-service-messenger_member_session.c gnunet-service-messenger_member_session.h \
  gnunet-service-messenger_sender_session.h \
  gnunet-service-messenger_member.c gnunet-service-messenger_member.h \
  gnunet-service-messenger_member_store.c gnunet-service-messenger_member_store.h \
  gnunet-service-messenger_message_handle.c gnunet-service-messenger_message_handle.h \
  gnunet-service-messenger_message_kind.c gnunet-service-messenger_message_kind.h \
  gnunet-service-messenger_message_recv.c gnunet-service-messenger_message_recv.h \
  gnunet-service-messenger_message_send.c gnunet-service-messenger_message_send.h \
  gnunet-service-messenger_message_state.c gnunet-service-messenger_message_state.h \
  gnunet-service-messenger_message_store.c gnunet-service-messenger_message_store.h \
  gnunet-service-messenger_operation_store.c gnunet-service-messenger_operation_store.h \
  gnunet-service-messenger_operation.c gnunet-service-messenger_operation.h \
  gnunet-service-messenger_peer_store.c gnunet-service-messenger_peer_store.h \
  gnunet-service-messenger_basement.c gnunet-service-messenger_basement.h \
  gnunet-service-messenger_handle.c gnunet-service-messenger_handle.h \
  gnunet-service-messenger_room.c gnunet-service-messenger_room.h \
  gnunet-service-messenger_tunnel.c gnunet-service-messenger_tunnel.h
gnunet_service_messenger_LDADD = \
  libgnunetmessenger.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
  test_messenger_api \
  test_messenger_anonymous

#check_SCRIPTS= \
#  test_messenger_start_testcase.sh

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

test_messenger_api_SOURCES = \
  test_messenger.c
test_messenger_api_LDADD = \
  libgnunetmessenger.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_messenger_anonymous_SOURCES = \
  test_messenger_anonymous.c
test_messenger_anonymous_LDADD = \
  libgnunetmessenger.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la

EXTRA_DIST = \
  test_messenger_start_testcase.sh \
  test_messenger_api.conf
