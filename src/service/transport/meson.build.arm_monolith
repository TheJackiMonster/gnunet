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
  foreach p : libgnunettransportapplication_src + libgnunettransportcore_src + libgnunettransportcommunicator_src + libgnunettransportmonitor_src + gnunetservicetransport_src + gnunetcommunicatorudp_src + gnunetcommunicatortcp_src
    gnunet_src += 'transport/' + p
  endforeach
endif

libgnunettransportapplication = library('gnunettransportapplication',
                                        libgnunettransportapplication_src,
                                        dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep],
                                        include_directories: [incdir, configuration_inc],
                                        install: true,
                                        install_dir: get_option('libdir'))
pkg.generate(libgnunettransportapplication, url: 'https://www.gnunet.org',
             description : 'Provides application APIs for accessing the transport service')
libgnunettransportapplication_dep = declare_dependency(link_with : libgnunettransportapplication)

libgnunettransportcore = library('gnunettransportcore',
                                 libgnunettransportcore_src,
                                 dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep],
                                 include_directories: [incdir, configuration_inc],
                                 install: true,
                                 install_dir: get_option('libdir'))
pkg.generate(libgnunettransportcore, url: 'https://www.gnunet.org',
             description : 'Provides core API for accessing the transport service')
libgnunettransportcore_dep = declare_dependency(link_with : libgnunettransportcore)

libgnunettransportcommunicator = library('gnunettransportcommunicator',
                                         libgnunettransportcommunicator_src,
                                         dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep],
                                         include_directories: [incdir, configuration_inc],
                                         install: true,
                                         install_dir: get_option('libdir'))
pkg.generate(libgnunettransportcommunicator, url: 'https://www.gnunet.org',
             description : 'Provides communicator API for accessing the transport service')
libgnunettransportcommunicator_dep = declare_dependency(link_with : libgnunettransportcommunicator)

libgnunettransportmonitor = library('gnunettransportmonitor',
                                    libgnunettransportmonitor_src,
                                    dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep],
                                    include_directories: [incdir, configuration_inc],
                                    install: true,
                                    install_dir: get_option('libdir'))
pkg.generate(libgnunettransportmonitor, url: 'https://www.gnunet.org',
             description : 'Provides monitor API for accessing the transport service')
libgnunettransportmonitor_dep = declare_dependency(link_with : libgnunettransportmonitor)



executable ('gnunet-service-transport',
            gnunetservicetransport_src,
            dependencies: [gcrypt_dep, sodium_dep, libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunethello_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           m_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-communicator-unix',
            gnunetcommunicatorunix_src,
            dependencies: [gcrypt_dep, sodium_dep, libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

if quic_dep.found() and get_option('experimental')
executable ('gnunet-communicator-quic',
            gnunetcommunicatortcp_src,
            dependencies: [gcrypt_dep, sodium_dep, libgnunettransportcommunicator_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetnat_dep,
                           gcrypt_dep,
                           quic_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
endif

configure_file(input : 'test_transport_defaults.conf',
               output : 'test_transport_defaults.conf',
               copy: true)

foreach p : ['unix', 'tcp', 'udp', 'quic']
  configure_file(input : 'test_communicator_'+p+'_basic_peer1.conf',
                 output : 'test_communicator_'+p+'_basic_peer1.conf',
                 copy: true)
  configure_file(input : 'test_communicator_'+p+'_basic_peer2.conf',
                 output : 'test_communicator_'+p+'_basic_peer2.conf',
                 copy: true)
endforeach

foreach p : ['tcp', 'udp']
  configure_file(input : 'test_communicator_'+p+'_rekey_peer1.conf',
                 output : 'test_communicator_'+p+'_rekey_peer1.conf',
                 copy: true)
  configure_file(input : 'test_communicator_'+p+'_rekey_peer2.conf',
                 output : 'test_communicator_'+p+'_rekey_peer2.conf',
                 copy: true)
endforeach

configure_file(input : 'test_communicator_udp_backchannel_peer1.conf',
               output : 'test_communicator_udp_backchannel_peer1.conf',
               copy: true)
configure_file(input : 'test_communicator_udp_backchannel_peer2.conf',
               output : 'test_communicator_udp_backchannel_peer2.conf',
               copy: true)

configure_file(input : 'test_communicator_tcp_bidirect_peer1.conf',
               output : 'test_communicator_tcp_bidirect_peer1.conf',
               copy: true)
configure_file(input : 'test_communicator_tcp_bidirect_peer2.conf',
               output : 'test_communicator_tcp_bidirect_peer2.conf',
               copy: true)


testtransport_test_names = [
    'test_transport_start_testcase',
    'test_transport_simple_send_performance',
    'test_transport_nat_icmp_tcp',
    'test_transport_nat_upnp',
    'test_transport_simple_send_string',
    'test_transport_simple_send',
    'test_transport_simple_send_broadcast',
    'test_transport_udp_backchannel',
    'test_transport_simple_send_dv_circle',
    'test_transport_simple_send_dv_inverse'
  ]

foreach t : testtransport_test_names

  test_filename = t + '.sh'
  test_file = configure_file(input : test_filename,
                             output : test_filename,
                             copy: true)

  if host_machine.system() != 'darwin'
    test(t, test_file, suite: 'transport', workdir: meson.current_build_dir(), is_parallel: false)
  endif
endforeach