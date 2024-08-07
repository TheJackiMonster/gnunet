# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-hello

gnunet_hello_SOURCES = \
 gnunet-hello.c
gnunet_hello_LDADD = \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_hello_LDFLAGS = \
  $(GN_LIBINTL)
