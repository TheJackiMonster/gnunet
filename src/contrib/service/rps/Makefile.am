# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  rps.conf

bin_PROGRAMS = gnunet-rps

gnunet_rps_SOURCES = \
  gnunet-rps.c

gnunet_rps_LDADD = \
  libgnunetrps.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(XLIB) $(GN_LIBINTL)

lib_LTLIBRARIES = libgnunetrps.la

libgnunetrps_la_SOURCES = \
 gnunet-service-rps_sampler_elem.h gnunet-service-rps_sampler_elem.c \
  rps-test_util.h rps-test_util.c \
  rps-sampler_common.h rps-sampler_common.c \
  rps-sampler_client.h rps-sampler_client.c \
  rps_api.c rps.h
libgnunetrps_la_LIBADD = \
  $(top_builddir)/src/service/nse/libgnunetnse.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetrps_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0
# Fix 'created both with libtool and without' error:
libgnunetrps_la_CFLAGS = $(AM_CFLAGS)


libexec_PROGRAMS = \
 gnunet-service-rps

gnunet_service_rps_SOURCES = \
 gnunet-service-rps_sampler_elem.h gnunet-service-rps_sampler_elem.c \
 rps-sampler_common.h rps-sampler_common.c \
 gnunet-service-rps_sampler.h gnunet-service-rps_sampler.c \
 gnunet-service-rps_custommap.h gnunet-service-rps_custommap.c \
 gnunet-service-rps_view.h gnunet-service-rps_view.c \
 gnunet-service-rps.c


gnunet_service_rps_LDADD = \
  libgnunetrps.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(top_builddir)/src/service/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/service/cadet/libgnunetcadet.la \
  $(top_builddir)/src/service/nse/libgnunetnse.la \
  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/service/core/libgnunetcore.la \
  $(LIBGCRYPT_LIBS) \
  -lm -lgcrypt \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_service_rps_view \
 test_service_rps_custommap \
 test_service_rps_sampler_elem
 # test_rps_single_req \
 # test_rps_churn
 # test_rps_sub \
 # test_rps_seed_request 
#if ENABLE_MALICIOUS
#check_PROGRAMS += \
# test_rps_malicious_1 \
# test_rps_malicious_2 \
# test_rps_malicious_3
#endif

rps_test_src = \
	test_rps.c \
	rps-test_util.h rps-test_util.c \
 gnunet-service-rps_sampler_elem.h gnunet-service-rps_sampler_elem.c \
 rps-sampler_common.h rps-sampler_common.c \
 gnunet-service-rps_sampler.h gnunet-service-rps_sampler.c

#ld_rps_test_lib = \
#	libgnunetrps.la \
#  $(top_builddir)/src/lib/util/libgnunetutil.la \
#  $(top_builddir)/src/service/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/testbed/libgnunettestbed.la \
#  -lm

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_service_rps_view_SOURCES = \
  gnunet-service-rps_view.h gnunet-service-rps_view.c \
  test_service_rps_view.c
test_service_rps_view_LDADD = $(top_builddir)/src/lib/util/libgnunetutil.la

test_service_rps_custommap_SOURCES = \
  gnunet-service-rps_custommap.h gnunet-service-rps_custommap.c \
  test_service_rps_custommap.c
test_service_rps_custommap_LDADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la

test_service_rps_sampler_elem_SOURCES = \
  gnunet-service-rps_sampler_elem.h gnunet-service-rps_sampler_elem.c \
  rps-test_util.h rps-test_util.c \
  test_service_rps_sampler_elem.c
test_service_rps_sampler_elem_LDADD = $(top_builddir)/src/lib/util/libgnunetutil.la

#test_rps_single_req_SOURCES = $(rps_test_src)
#test_rps_single_req_LDADD = $(ld_rps_test_lib)
#
#test_rps_seed_request_SOURCES = $(rps_test_src)
#test_rps_seed_request_LDADD = $(ld_rps_test_lib)
#
#test_rps_req_cancel_SOURCES = $(rps_test_src)
#test_rps_req_cancel_LDADD = $(ld_rps_test_lib)
#
#test_rps_sub_SOURCES = $(rps_test_src)
#test_rps_sub_LDADD = $(ld_rps_test_lib)
#
#test_rps_seed_big_SOURCES = $(rps_test_src)
#test_rps_seed_big_LDADD = $(ld_rps_test_lib)
#
#test_rps_churn_SOURCES = $(rps_test_src)
#test_rps_churn_LDADD = $(ld_rps_test_lib)
#
#test_rps_malicious_1_SOURCES = $(rps_test_src)
#test_rps_malicious_1_LDADD = $(ld_rps_test_lib)
#
#test_rps_malicious_2_SOURCES = $(rps_test_src)
#test_rps_malicious_2_LDADD = $(ld_rps_test_lib)
#
#test_rps_malicious_3_SOURCES = $(rps_test_src)
#test_rps_malicious_3_LDADD = $(ld_rps_test_lib)

EXTRA_DIST = \
  test_rps.conf
