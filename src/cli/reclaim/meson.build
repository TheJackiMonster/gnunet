executable(
    'gnunet-reclaim',
    'gnunet-reclaim.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetreclaim_dep,
        libgnunetidentity_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-did',
    'gnunet-did.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetreclaim_dep,
        libgnunetdid_dep,
        libgnunetgns_dep,
        libgnunetnamestore_dep,
        libgnunetidentity_dep,
        libgnunetutil_dep,
    ],
    include_directories: [
        incdir,
        configuration_inc,
        include_directories('../../service/reclaim'),
    ],
    install: true,
    install_dir: get_option('bindir'),
)

