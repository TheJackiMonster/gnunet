install_data(
    'datacache-0001.sql',
    'datacache-drop.sql',
    install_dir: get_option('datadir') / 'gnunet' / 'sql',
)

shared_module(
    'gnunet_plugin_datacache_sqlite',
    ['plugin_datacache_sqlite.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, sqlite_dep, libgnunetsq_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

shared_module(
    'gnunet_plugin_datacache_heap',
    ['plugin_datacache_heap.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

if pq_dep.found()
    shared_module(
        'gnunet_plugin_datacache_postgres',
        ['plugin_datacache_postgres.c'],
        install_rpath: get_option('prefix') / get_option('libdir'),
        dependencies: [libgnunetutil_dep, pq_dep, libgnunetpq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )
endif
