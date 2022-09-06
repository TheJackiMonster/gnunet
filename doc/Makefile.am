# This Makefile.am is in the public domain


if DOCUMENTATION
  SUBDIRS = doxygen
all-local:
	cd sphinx && make html

install-data-hook:
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr sphinx/_build/html $(DESTDIR)$(docdir)

sphinx/_build/man/gnunet.1: Makefile
	cd sphinx && make man

if INCLUDE_MANPAGES
# FIXME this is somehow broken on openbsd. See #7324
man_MANS = sphinx/_build/man/gnunet.1
SUBDIRS += man
endif
endif

EXTRA_DIST =							\
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE \
	sphinx/about.rst \
	sphinx/conf.py \
	sphinx/faq.rst \
	sphinx/gana.rst \
	sphinx/guis \
	sphinx/index.rst \
	sphinx/installing.rst \
	sphinx/livingstandards.rst \
	sphinx/make.bat \
	sphinx/man_developers \
	sphinx/man_users \
	sphinx/preface.rst \
	sphinx/_static \
	sphinx/Makefile


