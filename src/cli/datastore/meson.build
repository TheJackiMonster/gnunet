executable(
    'gnunet-datastore',
    ['gnunet-datastore.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetdatastore_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetdatacache_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
