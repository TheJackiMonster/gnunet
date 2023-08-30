executable(
    'gnunet-hello',
    ['gnunet-hello.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunethello_dep,
        libgnunetpils_dep,
        libgnunetpeerstore_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
