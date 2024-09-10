# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUBDIRS = scripts services

include Makefile.inc

INITD_FILES = \
  services/systemd/gnunet-user.service \
  services/systemd/sysusers-gnunet.conf \
  services/systemd/gnunet.service \
  services/systemd/tmpfiles-gnunet.conf \
  services/openrc/gnunet.initd

PACKAGES_FILES = \
	packages/fedora/10-dns2gns.sh \
	packages/fedora/gnunet-system.conf \
	packages/fedora/gnunet.service \
	packages/fedora/gnunet-user.service \
  packages/alpine/gnunet-gtk/APKBUILD \
  packages/alpine/gnurl/APKBUILD \
  packages/alpine/gnunet/gnunet-user-services.initd \
  packages/alpine/gnunet/gnunet.pre-deinstall \
  packages/alpine/gnunet/gnunet-user.conf \
  packages/alpine/gnunet/gnunet.xsession \
  packages/alpine/gnunet/gnunet-system.conf \
  packages/alpine/gnunet/APKBUILD \
  packages/alpine/gnunet/gnunet.post-install \
  packages/alpine/gnunet/gnunet.pre-install \
  packages/alpine/gnunet/gnunet-system-services.initd \
  packages/alpine/gnunet/gnunet-gns-proxy.initd \
  packages/arch/gnunet-git/gnunet.install \
  packages/arch/gnunet-git/gnunet-system.service \
  packages/arch/gnunet-git/gnunet.sysusers \
  packages/arch/gnunet-git/gnunet.tmpfiles \
  packages/arch/gnunet-git/gnunet-user.conf \
  packages/arch/gnunet-git/gnunet-user.service \
  packages/arch/gnunet-git/PKGBUILD \
  packages/arch/gnunet-git/.SRCINFO \
  packages/arch/gnunet/gnunet.install \
  packages/arch/gnunet/gnunet-system.service \
  packages/arch/gnunet/gnunet.sysusers \
  packages/arch/gnunet/gnunet.tmpfiles \
  packages/arch/gnunet/gnunet-user.conf \
  packages/arch/gnunet/gnunet-user.service \
  packages/arch/gnunet/PKGBUILD \
  packages/arch/gnunet/.SRCINFO \
  packages/guix/guix-env-py2.scm \
  packages/guix/guix-env-gillmann.scm \
  packages/guix/notest-guix-env.scm \
  packages/homebrew/gnunet.rb \
  packages/nix/gnunet-dev.nix \
  packages/nix/default.nix

EXTRA_DIST = \
  sounds/vonlynX-bdbAm-lo.wav \
  sounds/vonlynX-bdbG9-lo.wav \
  sounds/vonlynX-ringtones.txt \
  A-Z.ecc \
  xdg-scheme-handler/README.md \
  apparmor/gnunet-daemon-testbed-blacklist \
  apparmor/gnunet-service-identity \
  apparmor/gnunet-cadet \
  apparmor/gnunet-service-core \
  apparmor/gnunet-identity \
  apparmor/gnunet-service-cadet \
  apparmor/gnunet-service-dns \
  apparmor/gnunet-template \
  apparmor/gnunet-service-peerstore \
  apparmor/gnunet-nse \
  apparmor/gnunet-helper-transport-wlan \
  apparmor/gnunet-service-set \
  apparmor/gnunet-uri \
  apparmor/gnunet-conversation \
  apparmor/usr.bin.gnunet-helper-nat-server \
  apparmor/gnunet-transport \
  apparmor/gnunet-service-nse \
  apparmor/gnunet-transport-certificate-creation \
  apparmor/gnunet-daemon-hostlist \
  apparmor/gnunet-unindex \
  apparmor/gnunet-nat-server \
  apparmor/gnunet-setup \
  apparmor/gnunet-service-testbed \
  apparmor/gnunet-gtk \
  apparmor/gnunet-scalarproduct \
  apparmor/gnunet-statistics \
  apparmor/gnunet-helper-testbed \
  apparmor/gnunet-scrypt \
  apparmor/gnunet-conversation-test \
  apparmor/gnunet-publish \
  apparmor/gnunet-helper-audio-playback \
  apparmor/gnunet-revocation \
  apparmor/gnunet-helper-vpn \
  apparmor/gnunet-auto-share \
  apparmor/gnunet-service-scalarproduct-alice \
  apparmor/gnunet-service-template \
  apparmor/gnunet-arm \
  apparmor/gnunet-search \
  apparmor/gnunet-ecc \
  apparmor/gnunet-download-manager.scm \
  apparmor/gnunet-service-revocation \
  apparmor/gnunet-gns-proxy-setup-ca \
  apparmor/gnunet-service-mesh \
  apparmor/gnunet-helper-transport-wlan-dummy \
  apparmor/gnunet-service-conversation \
  apparmor/gnunet-fs \
  apparmor/gnunet-statistics-gtk \
  apparmor/gnunet-service-regex \
  apparmor/gnunet-helper-transport-bluetooth \
  apparmor/gnunet-service-resolver \
  apparmor/gnunet-service-fs \
  apparmor/gnunet-helper-nat-client \
  apparmor/gnunet-service-arm \
  apparmor/gnunet-peerinfo-gtk \
  apparmor/gnunet-vpn \
  apparmor/gnunet-helper-exit \
  apparmor/gnunet-set-profiler \
  apparmor/gnunet-helper-fs-publish \
  apparmor/gnunet-service-gns \
  apparmor/gnunet-service-datastore \
  apparmor/gnunet-service-namestore \
  apparmor/gnunet-service-dht \
  apparmor/gnunet-config \
  apparmor/gnunet-testbed-profiler \
  apparmor/gnunet-daemon-pt \
  apparmor/gnunet-peerinfo \
  apparmor/gnunet-service-ats \
  apparmor/gnunet-helper-audio-record \
  apparmor/gnunet-directory \
  apparmor/gnunet-download \
  apparmor/gnunet-fs-gtk \
  apparmor/tunables/gnunet \
  apparmor/gnunet-ats \
  apparmor/gnunet-set-ibf-profiler \
  apparmor/gnunet-dns2gns \
  apparmor/gnunet-service-peerinfo \
  apparmor/gnunet-service-namecache \
  apparmor/gnunet-daemon-exit \
  apparmor/gnunet-resolver \
  apparmor/gnunet-bcd \
  apparmor/gnunet-daemon-regexprofiler \
  apparmor/gnunet-namestore \
  apparmor/gnunet-namestore-gtk \
  apparmor/gnunet-service-testbed-logger \
  apparmor/gnunet-peerstore \
  apparmor/gnunet-core \
  apparmor/gnunet-gns-import.sh \
  apparmor/gnunet-gns-proxy \
  apparmor/gnunet-identity-gtk \
  apparmor/gnunet-service-vpn \
  apparmor/gnunet-daemon-testbed-underlay \
  apparmor/gnunet-qr \
  apparmor/gnunet-datastore \
  apparmor/gnunet-service-statistics \
  apparmor/gnunet-conversation-gtk \
  apparmor/gnunet-daemon-latency-logger \
  apparmor/gnunet-testing \
  apparmor/gnunet-namecache \
  apparmor/gnunet-service-transport \
  apparmor/gnunet-daemon-topology \
  apparmor/gnunet-helper-dns \
  apparmor/gnunet-gns \
  apparmor/gnunet-helper-nat-server \
  apparmor/abstractions/gnunet-test \
  apparmor/abstractions/gnunet-db \
  apparmor/abstractions/gnunet-gtk \
  apparmor/abstractions/gnunet-common \
  apparmor/abstractions/gnunet-suid \
  apparmor/abstractions/gnunet-sgid \
  apparmor/gnunet-service-scalarproduct-bob \
  conf/uncrustify.cfg \
  conf/tox.ini \
  conf/wireshark/wireshark.lua \
  conf/.style.yapf \
  conf/editors/eclipse/gnunet_codingstyle.xml \
  conf/editors/clang-format \
  conf/uncrustify_precommit \
  conf/gnunet/gnunet-user.conf \
  conf/gnunet/no_autostart_above_core.conf \
  conf/gnunet/gnunet-system.conf \
  conf/gnunet/no_forcestart.conf \
  conf/colorit/colorit.conf \
  conf/nss/nssswitch.conf \
  testbed_configs/testbed_cluster.conf \
  testbed_configs/testbed_supermuc.conf \
  packages/guix/guix.README \
  web/log.php \
  ci/buildbot/ssh-keys \
  ci/buildbot/ssh-config \
  docker/docker-entrypoint.sh \
  docker/Dockerfile \
  docker/README.md \
  benchmark/collect.awk \
  packages/guix/guix.scm \
  Makefile.inc \
  vagrant/Vagrantfile \
  vagrant/bootstrap.ubuntu.sh \
  privacy-sensitive-symbols.mspec \
  gnunet-arch-full.svg \
  patches/texi2html5-indent.diff \
  patches/transport_ats_years.diff \
  patches/lrn-indent.diff \
  test_gnunet_prefix.c \
  $(PACKAGES_FILES) \
  $(INITD_FILES)

check_PROGRAMS = \
  test_gnunet_prefix

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS)
endif

test_gnunet_prefix_SOURCES = \
  test_gnunet_prefix.c

test_gnunet_prefix_CPPFLAGS = \
  $(LTDLINCL) $(AM_CPPFLAGS)

test_gnunet_prefix_LDADD = \
  $(GCLIBADD) $(WINLIB) \
  $(LTLIBICONV) \
  $(GN_LIBINTL) \
  $(LIBLTDL) -lunistring $(XLIB)

aclocaldir = $(datadir)/aclocal
dist_aclocal_DATA = \
  gnunet.m4

xdgdeentrydir = $(datadir)/applications
dist_xdgdeentry_DATA = \
  xdg-scheme-handler/gnunet-uri.desktop

## EOF
