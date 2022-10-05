# This Makefile.am is in the public domain

SUBDIRS = .

if HAVE_DOXY_BINARY
  SUBDIRS += doxygen
endif

# OpenBSD is a bit iffy wrt sphinx make info
if OPENBSD
all-local:
	cd handbook/texinfo && make || touch gnunet.info
endif

install-data-hook:
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr handbook/html $(DESTDIR)$(docdir)
	mkdir -p $(DESTDIR)$(infodir)
	cp -pr handbook/texinfo/gnunet.info $(DESTDIR)$(infodir)

if INCLUDE_MANPAGES
SUBDIRS += man
endif

AM_MAKEINFOFLAGS = --no-headers --no-split

info_TEXINFOS = \
  handbook/texinfo/gnunet.texi

EXTRA_DIST = \
	handbook/texinfo \
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE \
	handbook/html
