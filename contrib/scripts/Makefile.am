# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUBDIRS = gnunet-logread

# FIXME: read into AWK_SCRIPTS autotools builtin.
if HAVE_AWK
awkSCRIPTS = \
  check-texinfo.awk
else
awkSCRIPTS =
endif

noinst_SCRIPTS = \
  terminate.py \
  pydiffer.py \
  removetrailingwhitespace.py \
  gnunet_pyexpect.py \
  gnunet_janitor.py \
  gnunet-chk.py \
  $(awkSCRIPTS)

bin_SCRIPTS = \
  gnunet-bugreport \
  gnunet-suidfix

EXTRA_DIST = \
  coverage.sh \
  terminate.py.in \
  gnunet_pyexpect.py.in \
  gnunet_janitor.py.in \
  gnunet-chk.py.in \
  removetrailingwhitespace.py.in \
  pydiffer.py.in \
  check-texinfo.awk.in \
  build-install-gnunet-debian10.sh \
  process_log.sh \
  generate-monkey-db.sh \
  find_typedefs.py \
  pydmesg \
  visualize_stats.sh \
  changelog_delta.sh \
  debug \
  build_cscope.sh \
  lint/lint-man.sh \
  lint/lint-python.sh \
  revisionary.sh \
  netjail/netjail_core.sh \
  netjail/netjail_setup_internet.sh \
  regression.sh \
  doc/texinfo-hacks.el \
  afferify \
  zonewalk-to-types.sh \
  gdb-iterate-dll.py \
  $(SCRIPTS)


CLEANFILES = \
  $(noinst_SCRIPTS)

# Use SUFFIX Extension rules, they are more portable for every
# implementation of 'make'.
# You'll also run into the "'%' is a GNU make extension warning"
# if you use this:
#
#%.py: %.py.in Makefile
#	$(do_subst) < $< > $@
#	chmod +x $@
#
# instead of this:
SUFFIXES = .py.in .py

.py.in.py:
	$(AWK) -v py="$(PYTHON)" -f $(top_srcdir)/bin/dosubst.awk < $< > $@
	chmod +x $@

if HAVE_AWK
check-texinfo.awk: check-texinfo.awk.in Makefile
	$(AWK) -v awkay="$(AWK_BINARY)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/check-texinfo.awk.in > check-texinfo.awk
	chmod +x check-texinfo.awk
endif
