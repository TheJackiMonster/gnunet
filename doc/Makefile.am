# This Makefile.am is in the public domain

# A note on sphinx:
# gnunet-handbook does not have a Makefile.am.
# It only supports building the documentation (and cleanup).
# So, the only targets used are "make (all)" and "make clean".
# Actuall installation of manpages/docs is done below
# Also, the manpages are handled in man/, but some of them are built using
# sphinx in all-local

SUBDIRS = .

if HAVE_DOXY_BINARY
  SUBDIRS += doxygen
endif

all-local:
	cd sphinx && make all

clean-local:
	cd sphinx && make clean

install-data-hook:
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr sphinx/_build/html $(DESTDIR)$(docdir)
	mkdir -p $(DESTDIR)$(infodir)
	cp -pr sphinx/_build/texinfo/gnunet.info $(DESTDIR)$(infodir)

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
	sphinx/_build/texinfo/gnunet.info \
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE \
	sphinx/_build/html \
	sphinx/about.rst \
	sphinx/conf.py \
	sphinx/faq.rst \
	sphinx/gana \
	sphinx/guis \
	sphinx/index.rst \
	sphinx/installing.rst \
	sphinx/livingstandards.rst \
	sphinx/make.bat \
	sphinx/developers \
	sphinx/users \
	sphinx/preface.rst \
	sphinx/_static \
	sphinx/Makefile
