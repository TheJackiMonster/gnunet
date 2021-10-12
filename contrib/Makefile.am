# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUBDIRS = scripts hellos services

include Makefile.inc

dist_pkgdata_DATA = \
  gns/gns-form.xslt \
  gns/gns-bcd.html \
  gns/def.tex \
  gns/bootstrap.min.css \
  gns/gns-form-fields.xml \
  gns/gns-bcd.tex \
  fcfsd/fcfsd-index.html \
  fcfsd/fcfsd-forbidden.html \
  fcfsd/fcfsd-notfound.html \
  branding/logo/gnunet-logo.png \
  branding/logo/lynXified-amirouche-v3.svg \
  branding/logo/gnunet-logo-dark-text.svg \
  branding/logo/gnunet-logo-color.png \
  branding/logo/lynXified-amirouche-anonymous-v3.png \
  branding/logo/gnunet-logo-dark-only-text.svg \
  branding/logo/gnunet-logo-big.png \
  branding/logo/gnunet-logo.pdf \
  testing_hostkeys.ecc \
  $(BUILDCOMMON_SHLIB_FILES)

INITD_FILES = \
  services/systemd/gnunet-user.service \
  services/systemd/sysusers-gnunet.conf \
  services/systemd/gnunet.service \
  services/systemd/tmpfiles-gnunet.conf \
  services/openrc/gnunet.initd

PACKAGES_FILES = \
  packages/guix/guix-env-py2.scm \
  packages/guix/guix-env-gillmann.scm \
  packages/guix/notest-guix-env.scm \
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
  packages/nix/gnunet-dev.nix \
  packages/nix/default.nix \
  packages/homebrew/gnunet.rb

EXTRA_DIST = \
  sounds/vonlynX-bdbAm-lo.wav \
  sounds/vonlynX-bdbG9-lo.wav \
  sounds/vonlynX-ringtones.txt \
  A-Z.ecc \
  xdg-scheme-handler/gnunet-uri.desktop \
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
  apparmor/gnunet-namestore-fcfsd \
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
  guix.README \
  web/log.php \
  ci/docker/docker-entrypoint.sh \
  ci/docker/Dockerfile \
  ci/buildbot/buildbot-update.sh \
  ci/buildbot/ssh-keys \
  ci/buildbot/ssh-config \
  docker/docker-entrypoint.sh \
  docker/Dockerfile \
  docker/README.md \
  docker/gnunet.conf \
  benchmark/collect.awk \
  gnunet_infrastructure/handbook_pull.sh \
  guix.scm \
  indent_pre-commit \
  Makefile.inc \
  gnunet.m4 \
  vagrant/Vagrantfile \
  vagrant/bootstrap.ubuntu.sh \
  privacy-sensitive-symbols.mspec \
  gnunet-arch-full.svg \
  patches/texi2html5-indent.diff \
  patches/transport_ats_years.diff \
  patches/lrn-indent.diff \
  test_gnunet_prefix.c \
  $(PACKAGES_FILES) \
  $(INITD_FILES) \
  $(BUILD_COMMON_FILES)

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
aclocal_DATA = \
  gnunet.m4

## EOF
