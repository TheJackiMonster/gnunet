# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunethello.la

libgnunethello_la_SOURCES = \
  hello-uri.c
libgnunethello_la_LIBADD = \
 $(top_builddir)/src/lib/util/libgnunetutil.la $(XLIB) \
 $(LTLIBINTL)
libgnunethello_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:1

check_PROGRAMS = \
 test_hello-uri

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_hello_uri_SOURCES = \
 test_hello-uri.c
test_hello_uri_LDADD = \
 libgnunethello.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 -lgcrypt
