executable ('gnunet-hello',
            ['gnunet-hello.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunethello_dep,
                           libgnunetpeerstore_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
