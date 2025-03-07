executable(
    'gnunet-core',
    ['gnunet-core.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetcore_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
