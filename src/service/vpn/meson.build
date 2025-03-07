libgnunetvpn_src = ['vpn_api.c']

gnunetservicevpn_src = ['gnunet-service-vpn.c']

exitdir = include_directories('../exit')

configure_file(
    input: 'vpn.conf.in',
    output: 'vpn.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetvpn_src + gnunetservicevpn_src
        gnunet_src += 'vpn/' + p
    endforeach
endif

libgnunetvpn = library(
    'gnunetvpn',
    libgnunetvpn_src,
    soversion: solibversions['libgnunetvpn']['soversion'],
    version: solibversions['libgnunetvpn']['version'],
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: get_option('prefix') / get_option('libdir'),
)
pkg.generate(
    libgnunetvpn,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the VPN service',
)
libgnunetvpn_dep = declare_dependency(link_with: libgnunetvpn)

executable(
    'gnunet-service-vpn',
    gnunetservicevpn_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetvpn_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetregex_dep,
        libgnunetcore_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc, exitdir],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
if host_machine.system() == 'linux'
    executable(
        'gnunet-helper-vpn',
        ['gnunet-helper-vpn.c'],
        install_rpath: get_option('prefix') / get_option('libdir'),
        dependencies: [libgnunetvpn_dep, libgnunetutil_dep],
        include_directories: [incdir, configuration_inc, exitdir],
        install: true,
        install_dir: get_option('libdir') / 'gnunet' / 'libexec',
    )
endif
