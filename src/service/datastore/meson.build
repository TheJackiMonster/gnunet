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

executable ('gnunet-service-datastore',
            gnunetservicedatastore_src,
            dependencies: [libgnunetdatastore_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetdatacache_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

testds_sqlite = executable ('test_store_api_sqlite',
            ['test_datastore_api.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_mgmt_sqlite = executable ('test_datastore_api_management_sqlite',
            ['test_datastore_api_management.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_plugin_sqlite = executable ('test_plugin_datastore_sqlite',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_heap = executable ('test_datastore_api_heap',
            ['test_datastore_api.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_mgmt_heap = executable ('test_datastore_api_management_heap',
            ['test_datastore_api_management.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_plugin_heap = executable ('test_plugin_datastore_heap',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_pq = executable ('test_datastore_api_postgres',
            ['test_datastore_api.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_plugin_pq = executable ('test_plugin_datastore_postgres',
            ['test_plugin_datastore.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testds_mgmt_pq = executable ('test_datastore_api_management_postgres',
            ['test_datastore_api_management.c'],
            dependencies: [
              libgnunetdatastore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

configure_file(input : 'test_defaults.conf',
               output : 'test_defaults.conf',
               copy: true)
configure_file(input : 'test_datastore_api_data_sqlite.conf',
               output : 'test_datastore_api_data_sqlite.conf',
               copy: true)
configure_file(input : 'test_datastore_api_data_heap.conf',
               output : 'test_datastore_api_data_heap.conf',
               copy: true)
configure_file(input : 'test_datastore_api_data_postgres.conf',
               output : 'test_datastore_api_data_postgres.conf',
               copy: true)

test('test_datastore_api_sqlite', testds_sqlite,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_datastore_api_management_sqlite', testds_mgmt_sqlite,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_plugin_datastore_sqlite', testds_plugin_sqlite,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_datastore_api_heap', testds_heap,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_datastore_api_management_heap', testds_mgmt_heap,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_plugin_datastore_heap', testds_plugin_heap,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_datastore_api_postgres', testds_pq,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_datastore_api_management_postgres', testds_mgmt_pq,
  suite: 'datastore', workdir: meson.current_build_dir())
test('test_plugin_datastore_postgres', testds_plugin_pq,
  suite: 'datastore', workdir: meson.current_build_dir())

