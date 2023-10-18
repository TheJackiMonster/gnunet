# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-dht-monitor \
 gnunet-dht-get \
 gnunet-dht-put \
 gnunet-dht-hello

gnunet_dht_get_SOURCES = \
 gnunet-dht-get.c
gnunet_dht_get_LDADD = \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_dht_get_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_hello_SOURCES = \
 gnunet-dht-hello.c
gnunet_dht_hello_LDADD = \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_dht_hello_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_put_SOURCES = \
 gnunet-dht-put.c
gnunet_dht_put_LDADD = \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_dht_put_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_monitor_SOURCES = \
 gnunet-dht-monitor.c
gnunet_dht_monitor_LDADD = \
  $(top_builddir)/src/service/dht/libgnunetdht.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_dht_monitor_LDFLAGS = \
  $(GN_LIBINTL)

