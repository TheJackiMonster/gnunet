configure_file(
    input: 'pt.conf',
    output: 'pt.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


executable(
    'gnunet-daemon-pt',
    ['gnunet-daemon-pt.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetdns_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetdht_dep,
        libgnunetcadet_dep,
        libgnunetvpn_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
