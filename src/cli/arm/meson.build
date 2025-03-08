gnunetarm_src = ['gnunet-arm.c']

executable(
    'gnunet-arm',
    gnunetarm_src,
    install_rpath: rpath_option,
    dependencies: [libgnunetarm_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
