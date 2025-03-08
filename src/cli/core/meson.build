executable(
    'gnunet-core',
    ['gnunet-core.c'],
    install_rpath: rpath_option,
    dependencies: [libgnunetcore_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
