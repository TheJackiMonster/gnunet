executable ('gnunet-revocation',
            ['gnunet-revocation.c'],
            dependencies: [libgnunetrevocation_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetsetu_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

