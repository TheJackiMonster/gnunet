# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

bin_PROGRAMS = \
 gnunet-nat-auto \
 gnunet-nat-server

gnunet_nat_server_SOURCES = \
 gnunet-nat-server.c
gnunet_nat_server_LDADD = \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_nat_server_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_nat_auto_SOURCES = \
  gnunet-nat-auto.c
gnunet_nat_auto_LDADD = \
  $(top_builddir)/src/service/nat-auto/libgnunetnatauto.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_nat_auto_LDFLAGS = \
  $(GN_LIBINTL)
