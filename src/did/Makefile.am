# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
	AM_CFLAGS = --coverage -O0
	XLIB = -lgcov
endif

bin_PROGRAMS = \
	gnunet-did

gnunet_did_SOURCES = \
	gnunet-did.c
gnunet_did_LDADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gns/libgnunetgns.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la

