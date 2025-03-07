executable(
    'gnunet-search',
    'gnunet-search.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, extractor_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-unindex',
    'gnunet-unindex.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-auto-share',
    'gnunet-auto-share.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-directory',
    'gnunet-directory.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, extractor_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-download',
    'gnunet-download.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-fs',
    'gnunet-fs.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetfs_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)
executable(
    'gnunet-publish',
    'gnunet-publish.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetfs_dep,
        extractor_dep,
        libgnunetidentity_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

