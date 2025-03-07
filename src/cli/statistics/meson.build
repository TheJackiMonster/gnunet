executable(
    'gnunet-statistics',
    ['gnunet-statistics.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetstatistics_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)


