libgnunettransport_src = ['transport_api_address_to_string.c',
                          'transport_api_blacklist.c',
                          'transport_api_core.c',
                          'transport_api_hello_get.c',
                          'transport_api_manipulation.c',
                          'transport_api_monitor_peers.c',
                          'transport_api_monitor_plugins.c',
                          'transport_api_offer_hello.c']
libgnunettransportapplication_src = ['transport_api2_application.c']
libgnunettransportcore_src = ['transport_api2_core.c']
libgnunettransportcommunicator_src = ['transport_api2_communication.c']
libgnunettransportmonitor_src = ['transport_api2_monitor.c']

gnunetservicetransport_src = ['gnunet-service-tng.c']
gnunetcommunicatortcp_src = ['gnunet-communicator-tcp.c']
gnunetcommunicatorudp_src = ['gnunet-communicator-udp.c']
gnunetcommunicatorunix_src = ['gnunet-communicator-unix.c']

configure_file(input : 'transport.conf.in',
               output : 'transport.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

configure_file(input : 'gnunet-transport-certificate-creation.in',
               output : 'gnunet-transport-certificate-creation',
               configuration : cdata,
               install: true,
               install_dir: get_option('bindir'))

configure_file(input : 'communicator-unix.conf',
               output : 'communicator-unix.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunettransport_src #+ libgnunettransportapplication_src + libgnunettransportcore_src + libgnunettransportcommunicator_src + libgnunettransportmonitor_src + gnunetservicetransport_src
    gnunet_src += 'transport/' + p
  endforeach
endif

libgnunettransport = library('gnunettransport',
        libgnunettransport_src,
        soversion: '2',
        version: '2.2.0',
        dependencies: [libgnunetutil_dep, libgnunetats_dep, libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunettransport, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the transport service')
libgnunettransport_dep = declare_dependency(link_with : libgnunettransport)

libgnunettransporttesting = library('gnunettransporttesting',
        [
          'transport-testing.c',
          'transport-testing-filenames.c',
          'transport-testing-loggers.c',
          'transport-testing-main.c',
          'transport-testing-send.c'
          ],
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunettesting_dep,
                       libgnunettransport_dep,
                       libgnunetats_dep,
                       libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))


libgnunettransportapplication = library('gnunettransportapplication',
        libgnunettransportapplication_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunettransportapplication, url: 'https://www.gnunet.org',
             description : 'Provides application APIs for accessing the transport service')
libgnunettransportapplication_dep = declare_dependency(link_with : libgnunettransportapplication)

libgnunettransportcore = library('gnunettransportcore',
        libgnunettransportcore_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunettransportcore, url: 'https://www.gnunet.org',
             description : 'Provides core API for accessing the transport service')
libgnunettransportcore_dep = declare_dependency(link_with : libgnunettransportcore)

libgnunettransportcommunicator = library('gnunettransportcommunicator',
        libgnunettransportcommunicator_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunettransportcommunicator, url: 'https://www.gnunet.org',
             description : 'Provides communicator API for accessing the transport service')
libgnunettransportcommunicator_dep = declare_dependency(link_with : libgnunettransportcommunicator)

libgnunettransportmonitor = library('gnunettransportmonitor',
        libgnunettransportmonitor_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunettransportmonitor, url: 'https://www.gnunet.org',
             description : 'Provides monitor API for accessing the transport service')
libgnunettransportmonitor_dep = declare_dependency(link_with : libgnunettransportmonitor)

libgnunettransporttesting2 = library('gnunettransporttesting2',
        [
          'transport_api_traits.c',
          'transport_api_cmd_connecting_peers.c',
          'transport_api_cmd_backchannel_check.c',
          'transport_api_cmd_start_peer.c',
          'transport_api_cmd_stop_peer.c',
          'transport_api_cmd_send_simple.c',
          'transport_api_cmd_send_simple_performance.c',
          'transport-testing2.c',
          'transport-testing-filenames2.c',
          'transport-testing-loggers2.c',
          'transport-testing-main2.c',
          'transport-testing-send2.c',
          'transport-testing-communicator.c',
          ],
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunettransportapplication_dep,
                       libgnunettransport_dep,
                       libgnunetpeerstore_dep,
                       libgnunetats_dep,
                       libgnunettesting_dep,
                       libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettransporttesting2_dep = declare_dependency(link_with : libgnunettransporttesting2)

executable ('gnunet-service-transport',
            gnunetservicetransport_src,
            dependencies: [libgnunettransport_dep, libgnunetutil_dep,
                           libgnunethello_dep,
                           libgnunetpeerstore_dep,
                           m_dep,
                           libgnunetstatistics_dep,
                           gcrypt_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-communicator-unix',
            gnunetcommunicatorunix_src,
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetnt_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
executable ('gnunet-communicator-udp',
            gnunetcommunicatorudp_src,
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunettransportapplication_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetnt_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
executable ('gnunet-communicator-tcp',
            gnunetcommunicatortcp_src,
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetnt_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-transport',
            ['gnunet-transport.c'],
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunethello_dep,
                           libgnunettransport_dep,
                           libgnunetpeerstore_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

libgnunettesttransport_cmd_simplesend = library('gnunet_test_transport_plugin_cmd_simple_send',
    ['test_transport_plugin_cmd_simple_send.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

libgnunettesttransport_cmd_simplesendbc = library('gnunet_test_transport_plugin_cmd_simple_send_broadcast',
    ['test_transport_plugin_cmd_simple_send_broadcast.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

libgnunettesttransport_cmd_simplesenddv = library('gnunet_test_transport_plugin_cmd_simple_send_dv',
    ['test_transport_plugin_cmd_simple_send_dv.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

libgnunettesttransport_cmd_simplesendperf = library('gnunet_test_transport_plugin_cmd_simple_send_performance',
    ['test_transport_plugin_cmd_simple_send_performance.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

libgnunettesttransport_cmd_udpback = library('gnunet_test_transport_plugin_cmd_udp_backchannel',
    ['test_transport_plugin_cmd_udp_backchannel.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

libgnunettesttransport_cmd_natupnp = library('gnunet_test_transport_plugin_cmd_nat_upnp',
    ['test_transport_plugin_cmd_nat_upnp.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransporttesting2_dep,
          libgnunettransportapplication_dep,
          libgnunettransportcore_dep,
          libgnunettesting_dep,
          libgnunetpeerstore_dep,
          libgnunetstatistics_dep,
          libgnunethello_dep,
          libgnunetarm_dep,
          libgnunetutil_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')
