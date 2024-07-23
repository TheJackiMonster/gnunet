# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

dist_pkgdata_DATA = \
  netjail/nat_node_test.sh \
  netjail/getmsg.sh \
  netjail/netjail_core.sh \
  netjail/netjail_start.sh \
  netjail/netjail_exec.sh \
  netjail/netjail_start_new.sh \
  netjail/netjail_stop.sh \
  netjail/netjail_test_master.sh \
  netjail/topo.sh \
  testing-ng/block.sh \
  testing-ng/emu_run.sh

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
	chmod o+x '$(DESTDIR)$(pkgdatadir)/nat_node_test.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/getmsg.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_core.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_start.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_start_new.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_exec.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_stop.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/netjail_test_master.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/topo.sh'
	chmod +x '$(DESTDIR)$(pkgdatadir)/block.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/emu_run.sh'

## EOF
