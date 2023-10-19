libgnunetdht_src = ['dht_api.c']

gnunetservicedht_src = ['gnunet-service-dht.c',
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

shared_module('gnunet_plugin_block_dht',
        ['plugin_block_dht.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunethello_dep,
                       libgnunetblock_dep,
                       libgnunetblockgroup_dep],
        include_directories: [incdir, configuration_inc],
              install:true,
              install_dir: get_option('libdir')/'gnunet')

executable ('gnunet-service-dht',
            gnunetservicedht_src,
            dependencies: [libgnunetdht_dep, libgnunetutil_dep,
                           libgnunetblock_dep,
                           m_dep,
                           libgnunetdatacache_dep,
                           libgnunetstatistics_dep,
                           libgnunetblockgroup_dep,
                           libgnunethello_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

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
