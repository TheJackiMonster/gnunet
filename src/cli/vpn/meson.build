executable(
    'gnunet-vpn',
    ['gnunet-vpn.c'],
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
    install_dir: get_option('bindir'),
)

