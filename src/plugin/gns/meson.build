shared_module(
    'gnunet_plugin_gnsrecord_gns',
    ['plugin_gnsrecord_gns.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)
shared_module(
    'gnunet_plugin_block_gns',
    ['plugin_block_gns.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetblockgroup_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

