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


if get_option('monolith') == false
  libgnunettransport = library('gnunettransport',
          libgnunettransport_src,
          dependencies: [libgnunetutil_dep, libgnunetats_dep, libgnunethello_dep],
          include_directories: [incdir, configuration_inc])
  libgnunettransport_dep = declare_dependency(link_with : libgnunettransport)

  libgnunettransportapplication = library('gnunettransportapplication',
          libgnunettransportapplication_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunettransportapplication_dep = declare_dependency(link_with : libgnunettransportapplication)

  libgnunettransportcore = library('gnunettransportcore',
          libgnunettransportcore_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunettransportcore_dep = declare_dependency(link_with : libgnunettransportcore)

  libgnunettransportcommunicator = library('gnunettransportcommunicator',
          libgnunettransportcommunicator_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunettransportcommunicator_dep = declare_dependency(link_with : libgnunettransportcommunicator)

  libgnunettransportmonitor = library('gnunettransportmonitor',
          libgnunettransportmonitor_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunettransportmonitor_dep = declare_dependency(link_with : libgnunettransportmonitor)
  executable ('gnunet-service-transport',
              gnunetservicetransport_src,
              dependencies: [libgnunettransport_dep, libgnunetutil_dep,
                             libgnunethello_dep,
                             libgnunetpeerstore_dep,
                             libgnunetstatistics_dep,
                             gcrypt_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunettransport_src + libgnunettransportapplication_src + libgnunettransportcore_src + libgnunettransportcommunicator_src + libgnunettransportmonitor_src + gnunetservicetransport_src
    gnunet_src += 'transport/' + p
  endforeach
endif
