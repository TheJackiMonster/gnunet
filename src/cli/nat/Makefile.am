# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

bin_PROGRAMS = \
 gnunet-nat

gnunet_nat_SOURCES = \
  gnunet-nat.c nat.h
gnunet_nat_LDADD = \
  $(top_builddir)/src/service/nat/libgnunetnatnew.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_nat_LDFLAGS = \
  $(GN_LIBINTL)
