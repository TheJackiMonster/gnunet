# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = \
  libgnunetblock.la \
  libgnunetblockgroup.la

libgnunetblock_la_SOURCES = \
  block.c
libgnunetblock_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunetblock_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  $(GN_LIBINTL) \
  -version-info 0:0:0

libgnunetblockgroup_la_SOURCES = \
  bg_bf.c
libgnunetblockgroup_la_LIBADD = \
  libgnunetblock.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
libgnunetblockgroup_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  $(GN_LIBINTL) \
  -version-info 0:0:0
