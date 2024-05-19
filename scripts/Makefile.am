# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

dist_pkgdata_DATA = \
  netjail/netjail_core.sh \
  netjail/netjail_start.sh \
  netjail/netjail_stop.sh \
  netjail/netjail_test_master.sh \
  netjail/topo.sh \
  testing-ng/block.sh

EXTRA_DIST = \
  get_version.sh \
	dosubst.awk \
	gana_update.sh \
	grephdr.sh \
	grepsrc.sh \
	pogen.sh \
	rename.sh \
	sphinx_update.sh

install-data-hook:
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_core.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_start.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_stop.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_test_master.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/topo.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/block.sh'

## EOF
