executable ('gnunet-messenger',
            'gnunet-messenger.c',
            dependencies: [libgnunetmessenger_dep,
                           libgnunetidentity_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

