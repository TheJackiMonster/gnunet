shared_module('gnunet_plugin_rest_namestore',
              ['plugin_rest_namestore.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetidentity_dep,
                             libgnunetgnsrecordjson_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetnamestore_dep,
                             libgnunetjson_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')


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

