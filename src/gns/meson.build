libgnunetgns_src = ['gns_api.c', 'gns_tld_api.c']

gnunetservicegns_src = ['gnunet-service-gns.c',
                        'gnunet-service-gns_resolver.c',
                        'gnunet-service-gns_interceptor.c']

gnunetgnsproxy_src = ['gnunet-gns-proxy.c']

configure_file(input : 'gns.conf.in',
               output : 'gns.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetgns = library('gnunetgns',
          libgnunetgns_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetgns_dep = declare_dependency(link_with : libgnunetgns)
  executable ('gnunet-gns',
              'gnunet-gns.c',
              dependencies: [libgnunetgns_dep,
                             libgnunetgnsrecord_dep,
                             idn_dep,
                             libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('bindir'))
  executable ('gnunet-gns-proxy',
              gnunetgnsproxy_src,
              dependencies: [libgnunetgns_dep,
                             libgnunetutil_dep,
                             mhd_dep,
                             idn_dep,
                             curl_dep,
                             gnutls_dep,
                             libgnunetidentity_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
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
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
else
  foreach p : libgnunetgns_src + gnunetservicegns_src
    gnunet_src += 'gns/' + p
  endforeach
endif
