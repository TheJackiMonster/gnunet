# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

dist_pkgdata_DATA = \
  netjail/netjail_core.sh \
  netjail/netjail_exec.sh \
  netjail/netjail_start.sh \
  netjail/netjail_stop.sh \
  netjail/topo.sh \
  testing-ng/block.sh

EXTRA_DIST = \
  get_version.sh

install-data-hook:
	chmod o+x '$(DESTDIR)$(pkgdatadir)/netjail_core.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/netjail_start.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/netjail_stop.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/netjail_exec.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/topo.sh'
	chmod o+x '$(DESTDIR)$(pkgdatadir)/block.sh'

## EOF
