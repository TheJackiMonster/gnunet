libgnunetpluginnamestore_sqlite_src = ['plugin_namestore_sqlite.c']

shared_module('gnunet_plugin_namestore_sqlite',
        libgnunetpluginnamestore_sqlite_src,
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetsq_dep,
                       sqlite_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

if pq_dep.found()
  shared_module('gnunet_plugin_namestore_postgres',
          ['plugin_namestore_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetpq_dep,
                         pq_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')
endif

