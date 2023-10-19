executable ('gnunet-revocation',
            ['gnunet-revocation.c'],
            dependencies: [libgnunetrevocation_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetsetu_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

executable ('gnunet-revocation-tvg',
            ['gnunet-revocation.c'],
            dependencies: [libgnunetrevocation_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

