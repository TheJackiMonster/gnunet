# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

libexec_PROGRAMS = \
  gnunet-cmds-helper

plugindir = $(libdir)/gnunet

lib_LTLIBRARIES = \
  libgnunettesting.la

gnunet_cmds_helper_SOURCES = \
  gnunet-cmds-helper.c
gnunet_cmds_helper_LDADD = $(XLIB) \
  libgnunettesting.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL) $(Z_LIBS)

libgnunettesting_la_SOURCES = \
  testing_api_cmd_barrier.c \
  testing_api_cmd_barrier_reached.c \
  testing_api_cmd_exec.c \
  testing_api_cmd_finish.c \
  testing_api_loop.c \
  testing_api_traits.c \
  testing_api_cmd_netjail_start.c \
  testing_api_cmd_netjail_start_cmds_helper.c \
  netjail.c netjail.h \
  barrier.c barrier.h \
  testing_api_cmd_batch.c
libgnunettesting_la_LIBADD = \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunettesting_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 3:0:0
