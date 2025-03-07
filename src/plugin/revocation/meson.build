shared_module(
    'gnunet_plugin_block_revocation',
    ['plugin_block_revocation.c'],
    dependencies: [
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

