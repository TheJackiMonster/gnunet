# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

# This program does not do anything.
bin_PROGRAMS = \
 gnunet-peerstore

gnunet_peerstore_SOURCES = \
 gnunet-peerstore.c
gnunet_peerstore_LDADD = \
  $(top_builddir)/src/lib/hello/libgnunethello.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(GN_LIBINTL)
