# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namecache.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

# testcases do not even build yet; thus: experimental!
TESTING_TESTS = \
 test_namecache_api_cache_block

if HAVE_SQLITE
check_PROGRAMS = \
 $(TESTING_TESTS)
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS)
endif

lib_LTLIBRARIES = \
  libgnunetnamecache.la


libgnunetnamecache_la_SOURCES = \
  namecache_api.c \
  namecache.h
libgnunetnamecache_la_LIBADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamecache_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-namecache

gnunet_service_namecache_SOURCES = \
 gnunet-service-namecache.c

gnunet_service_namecache_LDADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  libgnunetnamecache.la \
  $(GN_LIBINTL)


test_namecache_api_cache_block_SOURCES = \
 test_namecache_api_cache_block.c
test_namecache_api_cache_block_LDADD = \
  $(top_builddir)/src/lib/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/service/identity/libgnunetidentity.la \
  libgnunetnamecache.la \
  $(top_builddir)/src/service/testing/libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la


EXTRA_DIST = \
  test_namecache_api.conf
