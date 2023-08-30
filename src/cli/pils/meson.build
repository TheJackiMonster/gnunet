executable(
    'gnunet-pils',
    ['gnunet-pils.c'],
    install_rpath: rpath_option,
    dependencies: [libgnunetpils_dep, libgnunethello_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
