plugin_dep = [libgnunetutil_dep, libgnunetblock_dep, libgnunetblockgroup_dep]
shared_module(
    'gnunet_plugin_block_test',
    ['plugin_block_test.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: plugin_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

shared_module(
    'gnunet_plugin_block_template',
    ['plugin_block_template.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: plugin_dep,
    include_directories: [incdir, configuration_inc],
    install: false,
    install_dir: get_option('libdir') / 'gnunet',
)

