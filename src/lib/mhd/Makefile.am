# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetmhd.la

libgnunetmhd_la_LDFLAGS = \
  $(GN_LIBINTL) \
  -version-info 0:0:0 \
  -no-undefined
libgnunetmhd_la_CFLAGS = \
  $(MHD_CFLAGS) \
  $(AM_CFLAGS)
libgnunetmhd_la_SOURCES = \
  mhd_upload.c
libgnunetmhd_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lmicrohttpd \
  -ljansson \
  $(MHD_LIBS) \
  $(XLIB) \
  $(Z_LIBS)

check_PROGRAMS = \
  test_mhd

TESTS = \
  $(check_PROGRAMS)

test_json_mhd_SOURCES = \
  test_mhd.c
test_json_mhd_LDADD = \
  libgnunetjson.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  -lmicrohttpd \
  -ljansson \
  $(Z_LIBS) \
  @LIBCURL@
test_json_mhd_CFLAGS = $(MHD_CFLAGS) @LIBCURL_CPPFLAGS@ $(AM_CFLAGS)
