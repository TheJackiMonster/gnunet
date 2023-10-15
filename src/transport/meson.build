libgnunettransportapplication_src = ['transport_api2_application.c']
libgnunettransportcore_src = ['transport_api2_core.c']
libgnunettransportcommunicator_src = ['transport_api2_communication.c']
libgnunettransportmonitor_src = ['transport_api2_monitor.c']

gnunetservicetransport_src = ['gnunet-service-transport.c']
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

if get_option('monolith')
  foreach p : libgnunettransportapplication_src + libgnunettransportcore_src + libgnunettransportcommunicator_src + libgnunettransportmonitor_src + gnunetservicetransport_src
    gnunet_src += 'transport/' + p
  endforeach
  subdir_done()
endif

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
                       libgnunettransportcore_dep,
                       libgnunettransportapplication_dep,
                       libgnunetpeerstore_dep,
                       libgnunettesting_dep,
                       libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettransporttesting2_dep = declare_dependency(link_with : libgnunettransporttesting2)

executable ('gnunet-service-transport',
            gnunetservicetransport_src,
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunethello_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-communicator-unix',
            gnunetcommunicatorunix_src,
            dependencies: [libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
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
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

libgnunettesttransport_cmd_simplesend = library('gnunet_test_transport_plugin_cmd_simple_send',
    ['test_transport_plugin_cmd_simple_send.c'],
        dependencies: [
          libgnunetutil_dep,
          libgnunettransportapplication_dep,
          libgnunettransporttesting2_dep,
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
          libgnunettransportapplication_dep,
          libgnunettransporttesting2_dep,
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
          libgnunettransportapplication_dep,
          libgnunettransporttesting2_dep,
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
          libgnunettransportapplication_dep,
          libgnunettransporttesting2_dep,
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
          libgnunettransportapplication_dep,
          libgnunettransporttesting2_dep,
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
