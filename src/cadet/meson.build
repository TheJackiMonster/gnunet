libgnunetcadet_src = ['cadet_api.c',
                      'cadet_api_drop_message.c',
                      'cadet_api_get_channel.c',
                      'cadet_api_get_path.c',
                      'cadet_api_list_peers.c',
                      'cadet_api_list_tunnels.c',
                      'cadet_api_helper.c']

gnunetcadet_src = ['gnunet-cadet.c']
gnunetservicecadet_src = ['gnunet-service-cadet.c',
                          'gnunet-service-cadet_channel.c',
                          'gnunet-service-cadet_connection.c',
                          'gnunet-service-cadet_core.c',
                          'gnunet-service-cadet_dht.c',
                          'gnunet-service-cadet_hello.c',
                          'gnunet-service-cadet_tunnels.c',
                          'gnunet-service-cadet_paths.c',
                          'gnunet-service-cadet_peer.c']


if gnunet_monolith == false
  libgnunetcadet = library('gnunetcadet',
          libgnunetcadet_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetcadet_dep = declare_dependency(link_with : libgnunetcadet)
  executable ('gnunet-cadet',
              gnunetservicecadet_src,
              dependencies: [libgnunetcadet_dep,
                             libgnunetutil_dep,
                             libgnunetcore_dep,
                             libgnunetdht_dep,
                             libgnunetstatistics_dep,
                             libgnunetpeerinfo_dep,
                             libgnunetats_dep,
                             libgnunettransport_dep,
                             libgnunethello_dep],
              include_directories: [incdir, configuration_inc])
  executable ('gnunet-service-cadet',
              gnunetservicecadet_src,
              dependencies: [libgnunetcadet_dep,
                             libgnunetutil_dep,
                             libgnunetats_dep,
                             libgnunetcore_dep,
                             libgnunetdht_dep,
                             libgnunetstatistics_dep,
                             libgnunettransport_dep,
                             libgnunetpeerinfo_dep,
                             libgnunethello_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetcadet_src + gnunetservicecadet_src + gnunetcadet_src
    gnunet_src += 'cadet/' + p
  endforeach
endif
