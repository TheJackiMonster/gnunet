executable(
    'gnunet-namestore',
    ['gnunet-namestore.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnamestore_dep,
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-namestore-dbtool',
    ['gnunet-namestore-dbtool.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnamestore_dep,
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-namestore-zonefile',
    ['gnunet-namestore-zonefile.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnamestore_dep,
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
        idn_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-zoneimport',
    ['gnunet-zoneimport.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnamestore_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
        idn_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

