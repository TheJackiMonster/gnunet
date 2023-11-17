# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

AM_CLFAGS = -g

bin_PROGRAMS = \
 gnunet-messenger

gnunet_messenger_SOURCES = \
 gnunet-messenger.c
gnunet_messenger_LDADD = \
 $(top_builddir)/src/service/messenger/libgnunetmessenger.la \
 $(top_builddir)/src/service/identity/libgnunetidentity.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_messenger_LDFLAGS = \
  $(GN_LIBINTL)
