# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_LIBIDN
  LIBIDN= -lidn
else
  LIBIDN=
endif

if HAVE_LIBIDN2
  LIBIDN2= -lidn2
else
  LIBIDN2=
endif

USE_VPN = $(top_builddir)/src/service/vpn/libgnunetvpn.la

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la \
  libgnunet_plugin_gnsrecord_gns.la


libgnunet_plugin_gnsrecord_gns_la_SOURCES = \
  plugin_gnsrecord_gns.c
libgnunet_plugin_gnsrecord_gns_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/lib/block/libgnunetblock.la \
  $(top_builddir)/src/lib/block/libgnunetblockgroup.la \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_PLUGIN_LDFLAGS)

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
