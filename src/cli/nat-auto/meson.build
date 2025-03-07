executable(
    'gnunet-nat-auto',
    ['gnunet-nat-auto.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetnatauto_dep, libgnunetutil_dep, libgnunetnat_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-nat-server',
    ['gnunet-nat-server.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetnatauto_dep, libgnunetutil_dep, libgnunetnat_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

