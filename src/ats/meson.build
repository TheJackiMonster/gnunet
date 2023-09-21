libgnunetats_src = ['ats_api_connectivity.c',
                    'ats_api_scheduling.c',
                    'ats_api_scanner.c',
                    'ats_api_performance.c']

gnunetserviceats_src = ['gnunet-service-ats.c',
                        'gnunet-service-ats_addresses.c',
                        'gnunet-service-ats_connectivity.c',
                        'gnunet-service-ats_normalization.c',
                        'gnunet-service-ats_performance.c',
                        'gnunet-service-ats_plugins.c',
                        'gnunet-service-ats_preferences.c',
                        'gnunet-service-ats_scheduling.c',
                        'gnunet-service-ats_reservations.c']

if get_option('monolith') == false
  libgnunetats = library('gnunetats',
          libgnunetats_src,
          dependencies: [libgnunetutil_dep, libgnunethello_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetats_dep = declare_dependency(link_with : libgnunetats)
  executable ('gnunet-service-ats',
              gnunetserviceats_src,
              dependencies: [libgnunetats_dep, libgnunetutil_dep,
                             libgnunetnt_dep, libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
else
  foreach p : libgnunetats_src + gnunetserviceats_src
    gnunet_src += 'ats/' + p
  endforeach
endif
