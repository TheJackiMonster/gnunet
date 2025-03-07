configure_file(
    input: 'exit.conf',
    output: 'exit.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if host_machine.system() == 'linux'
    executable(
        'gnunet-helper-exit',
        ['gnunet-helper-exit.c'],
        install_rpath: get_option('prefix') / get_option('libdir'),
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet' / 'libexec',
    )
endif

executable(
    'gnunet-daemon-exit',
    ['gnunet-daemon-exit.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetdht_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetregex_dep,
        libgnunetcadet_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
