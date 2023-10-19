# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

bin_PROGRAMS = \
  gnunet-auto-share \
  gnunet-directory \
  gnunet-download \
  gnunet-publish \
  gnunet-search \
  gnunet-fs \
  gnunet-unindex

gnunet_directory_SOURCES = \
 gnunet-directory.c
gnunet_directory_LDADD = \
  $(top_builddir)/src/service/fs/libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_directory_LDADD += \
  -lextractor
endif

gnunet_fs_SOURCES = \
 gnunet-fs.c
gnunet_fs_LDADD = \
  $(top_builddir)/src/service/fs/libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_fs_LDADD += \
  -lextractor
endif

gnunet_download_SOURCES =  \
 gnunet-download.c
gnunet_download_LDADD =  \
 $(top_builddir)/src/service/fs/libgnunetfs.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)

gnunet_publish_SOURCES =  \
 gnunet-publish.c
gnunet_publish_LDADD =  \
 $(top_builddir)/src/service/identity/libgnunetidentity.la \
 $(top_builddir)/src/service/fs/libgnunetfs.la \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_publish_LDADD += \
  -lextractor
endif

gnunet_auto_share_SOURCES =  \
 gnunet-auto-share.c
gnunet_auto_share_LDADD =  \
 $(top_builddir)/src/lib/util/libgnunetutil.la \
 $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_auto_share_LDADD += \
  -lextractor
endif

gnunet_helper_fs_publish_SOURCES =  \
 gnunet-helper-fs-publish.c
gnunet_helper_fs_publish_LDADD =  \
  $(top_builddir)/src/service/fs/libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_helper_fs_publish_LDADD += \
  -lextractor
endif

gnunet_search_SOURCES = \
 gnunet-search.c
gnunet_search_LDADD = \
  $(top_builddir)/src/service/fs/libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_LIBEXTRACTOR
gnunet_search_LDADD += \
  -lextractor
endif


gnunet_unindex_SOURCES = \
 gnunet-unindex.c
gnunet_unindex_LDADD = \
  $(top_builddir)/src/service/fs/libgnunetfs.la \
  $(top_builddir)/src/lib/util/libgnunetutil.la \
  $(GN_LIBINTL)
