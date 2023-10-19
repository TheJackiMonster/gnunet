libgnunetnamestore_src = ['namestore_api.c', 'namestore_api_monitor.c']
libgnunetpluginnamestore_sqlite_src = ['plugin_namestore_sqlite.c']

gnunetnamestore_src = ['gnunet-namestore.c']
gnunetservicenamestore_src = ['gnunet-service-namestore.c']

configure_file(input : 'namestore.conf.in',
               output : 'namestore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetnamestore_src + gnunetservicenamestore_src
    gnunet_src += 'namestore/' + p
  endforeach
endif

libgnunetnamestore = library('gnunetnamestore',
        libgnunetnamestore_src,
        soversion: '0',
        version: '0.0.1',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetnamestore_dep = declare_dependency(link_with : libgnunetnamestore)
pkg.generate(libgnunetnamestore, url: 'https://www.gnunet.org',
             description : 'Provides API for storing GNS records to a database')

executable ('gnunet-service-namestore',
            gnunetservicenamestore_src,
            dependencies: [libgnunetnamestore_dep,
                           libgnunetutil_dep,
                           libgnunetnamecache_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
executable ('gnunet-namestore-fcfsd',
            ['gnunet-namestore-fcfsd.c'],
            dependencies: [libgnunetnamestore_dep,
                           libgnunetutil_dep,
                           libgnunetnamecache_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep,
                           mhd_dep,
                           json_dep,
                           libgnunetjson_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

