shared_module(
    'gnunet_plugin_namecache_sqlite',
    ['plugin_namecache_sqlite.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        sqlite_dep,
        libgnunetsq_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

if pq_dep.found()
    shared_module(
        'gnunet_plugin_namecache_postgres',
        ['plugin_namecache_postgres.c'],
        install_rpath: get_option('prefix') / get_option('libdir'),
        dependencies: [
            libgnunetutil_dep,
            libgnunetgnsrecord_dep,
            pq_dep,
            libgnunetpq_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )
endif

