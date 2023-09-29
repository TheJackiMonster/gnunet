libgnunetdatastore_src = ['datastore_api.c']

gnunetservicedatastore_src = ['gnunet-service-datastore.c']

configure_file(input : 'datastore.conf.in',
               output : 'datastore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

install_data ('datastore-0001.sql',
              'datastore-drop.sql',
               install_dir: get_option('datadir')/'gnunet'/'sql')

if get_option('monolith')
  foreach p : libgnunetdatastore_src + gnunetservicedatastore_src
    gnunet_src += 'datastore/' + p
  endforeach
endif
libgnunetdatastore = library('gnunetdatastore',
        libgnunetdatastore_src,
        soversion: '1',
        version: '1.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetstatistics_dep,
                       libgnunetdatacache_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetdatastore_dep = declare_dependency(link_with : libgnunetdatastore)
pkg.generate(libgnunetdatastore, url: 'https://www.gnunet.org',
             description : 'Management API for the datastore for persistent storage to disk')

shared_module('gnunet_plugin_datastore_sqlite',
        ['plugin_datastore_sqlite.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetdatastore_dep,
                       sqlite_dep,
                       libgnunetsq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')
shared_module('gnunet_plugin_datastore_heap',
        ['plugin_datastore_heap.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetdatacache_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

if pq_dep.found()
  shared_module('gnunet_plugin_datastore_postgres',
          ['plugin_datastore_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetdatastore_dep,
                         pq_dep,
                         libgnunetpq_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')
endif

executable ('gnunet-datastore',
            ['gnunet-datastore.c'],
            dependencies: [libgnunetdatastore_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetdatacache_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-service-datastore',
            gnunetservicedatastore_src,
            dependencies: [libgnunetdatastore_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetdatacache_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

