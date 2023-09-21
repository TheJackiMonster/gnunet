libgnunetreclaim_src = ['reclaim_api.c',
                        'reclaim_attribute.c',
                        'reclaim_credential.c']

gnunetservicereclaim_src = ['gnunet-service-reclaim.c',
                        'gnunet-service-reclaim_tickets.c']

configure_file(input : 'reclaim.conf',
               output : 'reclaim.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetreclaim = library('gnunetreclaim',
          libgnunetreclaim_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetreclaim_dep = declare_dependency(link_with : libgnunetreclaim)
  executable ('gnunet-reclaim',
              'gnunet-reclaim.c',
              dependencies: [libgnunetreclaim_dep,
                             libgnunetidentity_dep,
                             libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('bindir'))
  executable ('gnunet-service-reclaim',
              gnunetservicereclaim_src,
              dependencies: [libgnunetreclaim_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetgns_dep,
                             libgnunetidentity_dep,
                             libgnunetnamestore_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
else
  foreach p : libgnunetreclaim_src + gnunetservicereclaim_src
    gnunet_src += 'reclaim/' + p
  endforeach
endif
