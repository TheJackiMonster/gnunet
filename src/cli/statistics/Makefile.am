# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

bin_PROGRAMS = \
 gnunet-statistics

gnunet_statistics_SOURCES = \
 gnunet-statistics.c
gnunet_statistics_LDADD = \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

# Config file still in service folder
#if HAVE_PYTHON
#check_SCRIPTS = \
#  test_gnunet_statistics.py
#endif
#
#SUFFIXES = .py.in .py
#.py.in.py:
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $(srcdir)/$< > $@
#	chmod +x $@
#
#test_gnunet_statistics.py: test_gnunet_statistics.py.in Makefile
#	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/scripts/dosubst.awk < $(srcdir)/test_gnunet_statistics.py.in > test_gnunet_statistics.py
#	chmod +x test_gnunet_statistics.py
#
#EXTRA_DIST = \
#  test_statistics_api_data.conf \
#  test_gnunet_statistics.py.in
