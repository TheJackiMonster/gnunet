# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_messenger.la


libgnunet_plugin_gnsrecord_messenger_la_SOURCES = \
  plugin_gnsrecord_messenger.c
libgnunet_plugin_gnsrecord_messenger_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_messenger_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


pkgcfg_DATA = \
  messenger.conf

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

libexec_PROGRAMS = \
 gnunet-service-messenger \
 $(EXP_LIBEXEC)

lib_LTLIBRARIES = \
  libgnunetmessenger.la \
  $(EXP_LIB)

libgnunetmessenger_la_SOURCES = \
  messenger_api.c \
  messenger_api_ego.h \
  messenger_api_contact.c messenger_api_contact.h \
  messenger_api_contact_store.c messenger_api_contact_store.h \
  messenger_api_message.c messenger_api_message.h \
  messenger_api_list_tunnels.c messenger_api_list_tunnels.h \
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

gnunet_service_messenger_SOURCES = \
  gnunet-service-messenger.c gnunet-service-messenger.h \
  gnunet-service-messenger_service.c gnunet-service-messenger_service.h \
  gnunet-service-messenger_list_handles.c gnunet-service-messenger_list_handles.h \
  gnunet-service-messenger_list_messages.c gnunet-service-messenger_list_messages.h \
  gnunet-service-messenger_member_session.c gnunet-service-messenger_member_session.h \
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
  gnunet-service-messenger_basement.c gnunet-service-messenger_basement.h \
  gnunet-service-messenger_ego_store.c gnunet-service-messenger_ego_store.h \
  gnunet-service-messenger_handle.c gnunet-service-messenger_handle.h \
  gnunet-service-messenger_room.c gnunet-service-messenger_room.h \
  gnunet-service-messenger_tunnel.c gnunet-service-messenger_tunnel.h
gnunet_service_messenger_LDADD = \
  libgnunetmessenger.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

check_PROGRAMS = test_messenger_anonymous

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 $(check_PROGRAMS)
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
  test_messenger_api.conf
