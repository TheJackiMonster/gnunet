# This Makefile.am is in the public domain

SUBDIRS = .

if HAVE_DOXY_BINARY
  SUBDIRS += doxygen
endif

sphinx/_build/texinfo/gnunet.info:
	cd sphinx && make info

sphinx/_build/html:
	cd sphinx && make html

sphinx: sphinx/_build/texinfo/gnunet.info sphinx/_build/html
	cd sphinx && make html info

install-data-hook: sphinx
	mkdir -p $(DESTDIR)$(docdir)
	cp -pr sphinx/_build/html $(DESTDIR)$(docdir)
	mkdir -p $(DESTDIR)$(infodir)
	cp -pr sphinx/_build/texinfo/gnunet.info $(DESTDIR)$(infodir)

clean-local:
	cd sphinx && make clean

sphinx/_build/man/gnunet.1:
	cd sphinx && make man

sphinx-man:
	cd sphinx && make man

.DEFAULT: sphinx-man

if INCLUDE_MANPAGES
man_MANS = \
	sphinx/_build/man/gnunet.1 \
	sphinx/_build/man/gnunet.2 \
	sphinx/_build/man/gnunet.3 \
	sphinx/_build/man/gnunet.4 \
	sphinx/_build/man/gnunet.5 \
	sphinx/_build/man/gnunet.6 \
	sphinx/_build/man/gnunet.7 \
	sphinx/_build/man/gnunet.8 \
	sphinx/_build/man/gnunet.9 \
	sphinx/_build/man/gana.1 \
	sphinx/_build/man/gana.2 \
	sphinx/_build/man/gana.3 \
	sphinx/_build/man/gana.4 \
	sphinx/_build/man/gana.5 \
	sphinx/_build/man/gnunet-dev.1 \
	sphinx/_build/man/gnunet-dev.2 \
	sphinx/_build/man/gnunet-dev.3 \
	sphinx/_build/man/gnunet-dev.4 \
	sphinx/_build/man/gnunet-dev.5 \
	sphinx/_build/man/gnunet-dev.6 \
	sphinx/_build/man/lsd.1
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
	$(man_MANS) \
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
