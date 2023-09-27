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
  foreach p : libgnunetnamestore_src + libgnunetpluginnamestore_sqlite_src + gnunetservicenamestore_src
    gnunet_src += 'namestore/' + p
  endforeach
  subdir_done()
endif

libgnunetnamestore = library('gnunetnamestore',
        libgnunetnamestore_src,
        soversion: '0',
        version: '0.1.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetnamestore_dep = declare_dependency(link_with : libgnunetnamestore)
pkg.generate(libgnunetnamestore, url: 'https://www.gnunet.org',
             description : 'Provides API for storing GNS records to a database')

shared_module('gnunet_plugin_namestore_sqlite',
        libgnunetpluginnamestore_sqlite_src,
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep,
                       libgnunetsq_dep,
                       libgnunetstatistics_dep,
                       sqlite_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

if pq_dep.found()
  shared_module('gnunet_plugin_namestore_postgres',
          ['plugin_namestore_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep,
                         libgnunetpq_dep,
                         libgnunetstatistics_dep,
                         pq_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')
endif

executable ('gnunet-namestore',
          gnunetnamestore_src,
          dependencies: [libgnunetnamestore_dep,
                         libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('bindir'))
executable ('gnunet-namestore-dbtool',
            ['gnunet-namestore-dbtool.c'],
            dependencies: [libgnunetnamestore_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-namestore-zonefile',
            ['gnunet-namestore-zonefile.c'],
            dependencies: [libgnunetnamestore_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-zoneimport',
            ['gnunet-zoneimport.c'],
            dependencies: [libgnunetnamestore_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
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

