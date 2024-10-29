install_data ('datastore-0001.sql',
              'datastore-drop.sql',
               install_dir: get_option('datadir')/'gnunet'/'sql')

shared_module('gnunet_plugin_datastore_sqlite',
        ['plugin_datastore_sqlite.c'],
        dependencies: [libgnunetutil_dep,
                       sqlite_dep,
                       libgnunetsq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

shared_module('gnunet_plugin_datastore_heap',
        ['plugin_datastore_heap.c'],
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

if pq_dep.found()
  shared_module('gnunet_plugin_datastore_postgres',
          ['plugin_datastore_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         pq_dep,
                         libgnunetpq_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')
endif

testds_plugin_sqlite = executable ('test_plugin_datastore_sqlite',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

perfds_plugin_sqlite = executable ('perf_plugin_datastore_sqlite',
            ['perf_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)


testds_plugin_heap = executable ('test_plugin_datastore_heap',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_plugin_pq = executable ('test_plugin_datastore_postgres',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

perfds_plugin_heap = executable ('perf_plugin_datastore_heap',
            ['perf_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

perfds_plugin_pq = executable ('perf_plugin_datastore_postgres',
            ['perf_plugin_datastore.c'],
            dependencies: [
              libgnunetutil_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)


configure_file(input : 'test_defaults.conf',
               output : 'test_defaults.conf',
               copy: true)
configure_file(input : 'test_plugin_datastore_data_sqlite.conf',
               output : 'test_plugin_datastore_data_sqlite.conf',
               copy: true)
configure_file(input : 'test_plugin_datastore_data_heap.conf',
               output : 'test_plugin_datastore_data_heap.conf',
               copy: true)
configure_file(input : 'test_plugin_datastore_data_postgres.conf',
               output : 'test_plugin_datastore_data_postgres.conf',
               copy: true)

test('test_plugin_datastore_sqlite', testds_plugin_sqlite,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_plugin_datastore_heap', testds_plugin_heap,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_plugin_datastore_postgres', testds_plugin_pq,
  suite: 'datastore', workdir: meson.current_build_dir())
test('perf_plugin_datastore_sqlite', perfds_plugin_sqlite,
  suite: ['datastore', 'perf'], workdir: meson.current_build_dir())
test('perf_plugin_datastore_heap', perfds_plugin_heap,
  suite: ['datastore', 'perf'], workdir: meson.current_build_dir())
test('perf_plugin_datastore_postgres', perfds_plugin_pq,
  suite: ['datastore', 'perf'], workdir: meson.current_build_dir())
