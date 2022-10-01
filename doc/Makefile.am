# This Makefile.am is in the public domain

SUBDIRS = .

if HAVE_DOXY_BINARY
  SUBDIRS += doxygen
endif

install-data-hook:
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr handbook/html $(DESTDIR)$(docdir)
	mkdir -p $(DESTDIR)$(infodir)
	cp -pr handbook/texinfo/gnunet.info $(DESTDIR)$(infodir)

if INCLUDE_MANPAGES
SUBDIRS += man
endif

# NOTE: We cannot make this conditional because automake
# This means that if documentation is built, you MUST also build texinfos
# and need makeinfo.
# And yes, sphinx already compiled texi->info at this point and this will
# re-create it.
# So, we now manually copy it above in the install-data-hook
#info_TEXINFOS = \
#  sphinx/_build/texinfo/gnunet.texi

EXTRA_DIST = \
	handbook/texinfo/gnunet.info \
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE \
	handbook/html
