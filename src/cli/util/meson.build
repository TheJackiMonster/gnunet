executable(
    'gnunet-base32',
    ['gnunet-base32.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-config',
    ['gnunet-config.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-resolver',
    ['gnunet-resolver.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-ecc',
    ['gnunet-ecc.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, gcrypt_dep, m_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-scrypt',
    ['gnunet-scrypt.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-uri',
    ['gnunet-uri.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
if zbar_dep.found()
    executable(
        'gnunet-qr',
        ['gnunet-qr.c'],
        install_rpath: get_option('prefix') / get_option('libdir'),
        dependencies: [zbar_dep, libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('bindir'),
    )
endif
executable(
    'gnunet-config-diff',
    ['gnunet-config-diff.c'],
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)

executable(
    'gnunet-timeout',
    ['gnunet-timeout.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-crypto-tvg',
    ['gnunet-crypto-tvg.c'],
    dependencies: [libgnunetutil_dep, json_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)

