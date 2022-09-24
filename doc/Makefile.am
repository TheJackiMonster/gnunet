# This Makefile.am is in the public domain

if DOCUMENTATION
  SUBDIRS = . doxygen
all-local:
	cd sphinx && make html

install-data-hook:
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr sphinx/_build/html $(DESTDIR)$(docdir)

if INCLUDE_MANPAGES
man_MANS = sphinx/_build/man/gnunet.1
SUBDIRS += man
endif
endif

info_TEXINFOS = \
  sphinx/_build/texinfo/gnunet.texi

EXTRA_DIST = \
    sphinx/_build/man/gnunet.1 \
    sphinx/_build/texinfo/gnunet.texinfo \
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE \
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
