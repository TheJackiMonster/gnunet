executable ('gnunet-identity',
            ['gnunet-identity.c'],
            dependencies: [libgnunetidentity_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

