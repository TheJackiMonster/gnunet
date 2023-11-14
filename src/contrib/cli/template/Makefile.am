# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_PROGRAMS = \
 gnunet-template


gnunet_template_SOURCES = \
 gnunet-template.c
gnunet_template_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la
gnunet_template_LDFLAGS = \
  $(GN_LIBINTL)
