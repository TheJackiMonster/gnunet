libgnunetdht_src = ['dht_api.c']

gnunetservicedht_src = ['gnunet-service-dht.c',
                        'plugin_dhtu_gnunet.c',
                        'plugin_dhtu_ip.c',
                        'gnunet-service-dht_datacache.c',
                        'gnunet-service-dht_neighbours.c',
                        'gnunet-service-dht_routing.c']

configure_file(input : 'dht.conf.in',
               output : 'dht.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetdht_src + gnunetservicedht_src
    gnunet_src += 'dht/' + p
  endforeach
endif

libgnunetdht = library('gnunetdht',
        libgnunetdht_src,
        soversion: '4',
        version: '4.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetdht_dep = declare_dependency(link_with : libgnunetdht)
pkg.generate(libgnunetdht, url: 'https://www.gnunet.org',
           description : 'Provides API for the R5N distributed hash table')

executable ('gnunet-service-dht',
            gnunetservicedht_src,
            dependencies: [libgnunetdht_dep, libgnunetutil_dep,
                           libgnunetblock_dep,
                           libgnunetcore_dep,
                           libgnunetnse_dep,
                           libgnunettransportapplication_dep,
                           libgnunetpeerstore_dep,
                           m_dep,
                           libgnunetdatacache_dep,
                           libgnunetstatistics_dep,
                           libgnunetblockgroup_dep,
                           libgnunethello_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

configure_file(input : 'dhtu.conf',
               output : 'dhtu.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

libgnunettestingdhtu = library('gnunettestingdhtu',
        ['testing_dhtu_cmd_send.c'],
        soversion: '0',
        version: '0.0.0',
        dependencies: [
          libgnunetutil_dep,
          libgnunetarm_dep,
          libgnunettesting_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettestingdhtu_dep = declare_dependency(link_with : libgnunettestingdhtu)

configure_file(input : 'test_dht_api_data.conf',
               output : 'test_dht_api_data.conf',
               copy: true)

testdht_api = executable ('test_dht_api',
            ['test_dht_api.c'],
            dependencies: [libgnunetdht_dep,
                           libgnunetutil_dep,
                           libgnunettesting_dep,
                           libgnunethello_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

test('test_dht_api', testdht_api, suite: 'dht',
     workdir: meson.current_build_dir())

testdhtu_ip = executable('test_dhtu_ip',
           ['test_dhtu_ip.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunettesting_dep],
          include_directories: [incdir, configuration_inc],
          install: false)

test('test_dhtu_ip', testdhtu_ip, suite: 'dhtu',
     workdir: meson.current_build_dir())


