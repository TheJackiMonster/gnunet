libgnunetcore_src = ['core_api.c',
                    'core_api_monitor_peers.c']

gnunetservicecore_src = ['gnunet-service-core.c',
                        'gnunet-service-core_kx.c',
                        'gnunet-service-core_sessions.c',
                        'gnunet-service-core_typemap.c']



if gnunet_monolith == false
  libgnunetcore = library('gnunetcore',
          libgnunetcore_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetcore_dep = declare_dependency(link_with : libgnunetcore)
  executable ('gnunet-service-core',
              gnunetservicecore_src,
              dependencies: [libgnunetcore_dep, libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunettransport_dep,
                             zlib_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetcore_src + gnunetservicecore_src
    gnunet_src += 'core/' + p
  endforeach
endif
