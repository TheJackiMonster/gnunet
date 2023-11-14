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

configure_file(copy: true,
               input: 'test_plugin_namestore_sqlite.conf',
               output: 'test_plugin_namestore_sqlite.conf')

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
configure_file(copy: true,
               input: 'test_plugin_namestore_postgres.conf',
               output: 'test_plugin_namestore_postgres.conf')

  testpluginnamestore_pq = executable ('test_plugin_namestore_postgres',
              ['test_plugin_namestore.c'],
              dependencies: [
                libgnunetutil_dep
              ],
              include_directories: [incdir, configuration_inc],
              install: false)
  test('test_plugin_namestore_postgres', testpluginnamestore_pq, workdir: meson.current_build_dir(),
     suite: 'namestore')
endif

testpluginnamestore_sq = executable ('test_plugin_namestore_sqlite',
            ['test_plugin_namestore.c'],
            dependencies: [
              libgnunetutil_dep
            ],
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_plugin_namestore_sqlite', testpluginnamestore_sq, workdir: meson.current_build_dir(),
   suite: 'namestore')

