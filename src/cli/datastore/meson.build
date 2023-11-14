executable ('gnunet-datastore',
            ['gnunet-datastore.c'],
            dependencies: [libgnunetdatastore_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetdatacache_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
