configure_file(input : 'testbed.conf',
               output : 'testbed.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  subdir_done()
endif
executable ('gnunet-helper-testbed',
            ['gnunet-helper-testbed.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep,
                           zlib_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
executable ('gnunet-daemon-testbed-blacklist',
            ['gnunet-daemon-testbed-blacklist.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

executable ('gnunet-daemon-underlay',
            ['gnunet-daemon-testbed-underlay.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep,
                           sqlite_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
