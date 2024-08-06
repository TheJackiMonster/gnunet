executable ('gnunet-core',
            ['gnunet-core.c'],
            dependencies: [libgnunetcore_dep,
                           libgnunetutil_dep,
                           libgnunethello_dep,
                           libgnunetpeerstore_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
