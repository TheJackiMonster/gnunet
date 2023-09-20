libgnunetgns_src = ['gns_api.c', 'gns_tld_api.c']

gnunetservicegns_src = ['gnunet-service-gns.c',
                        'gnunet-service-gns_resolver.c',
                        'gnunet-service-gns_interceptor.c']


if gnunet_monolith == false
  libgnunetgns = library('gnunetgns',
          libgnunetgns_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetgns_dep = declare_dependency(link_with : libgnunetgns)
  executable ('gnunet-service-gns',
              gnunetservicegns_src,
              dependencies: [libgnunetgns_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetdht_dep,
                             libgnunetdns_dep,
                             idn_dep,
                             libgnunetidentity_dep,
                             libgnunetnamecache_dep,
                             libgnunetrevocation_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetgns_src + gnunetservicegns_src
    gnunet_src += 'gns/' + p
  endforeach
endif
