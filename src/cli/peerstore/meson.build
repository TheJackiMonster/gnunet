executable ('gnunet-peerstore',
            'gnunet-peerstore.c',
            dependencies: [libgnunetpeerstore_dep,
                           libgnunetutil_dep,
                           libgnunethello_dep
                          ],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

