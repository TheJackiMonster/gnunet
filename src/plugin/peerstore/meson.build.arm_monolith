shared_module('gnunet_plugin_peerstore_sqlite',
        ['plugin_peerstore_sqlite.c'],
        dependencies: [sodium_dep, gcrypt_dep, libgnunetutil_dep,
                       libgnunetsq_dep,
                       sqlite_dep],
        include_directories: [incdir,
                              configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')
