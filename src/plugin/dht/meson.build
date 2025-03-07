shared_module(
    'gnunet_plugin_block_dht',
    ['plugin_block_dht.c'],
    dependencies: [
        libgnunetutil_dep,
        libgnunethello_dep,
        libgnunetblock_dep,
        libgnunetblockgroup_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)
