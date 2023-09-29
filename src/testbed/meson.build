libgnunettestbed_src = [
  'testbed_api.c',
  'testbed_api_hosts.c',
  'testbed_api_operations.c',
  'testbed_api_peers.c',
  'testbed_api_services.c',
  'testbed_api_statistics.c',
  'testbed_api_testbed.c',
  'testbed_api_test.c',
  'testbed_api_topology.c',
  'testbed_api_sd.c',
  'testbed_api_barriers.c'
  ]

configure_file(input : 'testbed.conf',
               output : 'testbed.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  subdir_done()
endif

libgnunettestbed = library('gnunettestbed',
        libgnunettestbed_src,
        soversion: '0',
        version: '0.1.0',
        dependencies: [libgnunetutil_dep,
                       m_dep,
                       zlib_dep,
                       libgnunetstatistics_dep,
                       libgnunethello_dep,
                       libgnunettesting_dep,
                       libgnunettransport_dep,
                       libgnunetarm_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettestbed_dep = declare_dependency(link_with : libgnunettestbed)
pkg.generate(libgnunettestbed, url: 'https://www.gnunet.org',
             description : 'Provides API for testbed')


executable ('gnunet-helper-testbed',
            ['gnunet-helper-testbed.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettestbed_dep,
                           libgnunettesting_dep,
                           libgnunettransport_dep,
                           zlib_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
executable ('gnunet-daemon-testbed-blacklist',
            ['gnunet-daemon-testbed-blacklist.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

executable ('gnunet-daemon-underlay',
            ['gnunet-daemon-testbed-underlay.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunethello_dep,
                           libgnunetpeerinfo_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep,
                           sqlite_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

executable ('gnunet-service-testbed',
            ['gnunet-service-testbed.c',
             'gnunet-service-testbed_links.c',
             'gnunet-service-testbed_peers.c',
             'gnunet-service-testbed_cache.c',
             'gnunet-service-testbed_oc.c',
             'gnunet-service-testbed_cpustatus.c',
             'gnunet-service-testbed_meminfo.c',
             'gnunet-service-testbed_barriers.c',
             'gnunet-service-testbed_connectionpool.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunetats_dep,
                           libgnunetarm_dep,
                           libgnunethello_dep,
                           libgnunettestbed_dep,
                           libgnunettesting_dep,
                           libgnunettransport_dep,
                           zlib_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

executable ('gnunet-daemon-latency-logger',
            ['gnunet-daemon-latency-logger.c'],
            dependencies: [libgnunetutil_dep,
                           libgnunetats_dep,
                           sqlite_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
