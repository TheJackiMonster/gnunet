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
configure_file(input : 'tlds.conf',
               output : 'tlds.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

configure_file(input : 'gnunet-gns-proxy-setup-ca.in',
               output : 'gnunet-gns-proxy-setup-ca',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

install_data('gnunet-gns-proxy-ca.template',
             install_dir: get_option('datadir')/'gnunet')

if get_option('monolith')
  foreach p : libgnunetgns_src + gnunetservicegns_src
    gnunet_src += 'gns/' + p
  endforeach
  subdir_done()
endif

libgnunetgns = library('gnunetgns',
        libgnunetgns_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetgns_dep = declare_dependency(link_with : libgnunetgns)
pkg.generate(libgnunetgns, url: 'https://www.gnunet.org',
             description : 'Provides API to access the GNU Name System')

shared_module('gnunet_plugin_gnsrecord_gns',
        ['plugin_gnsrecord_gns.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')
shared_module('gnunet_plugin_block_gns',
              ['plugin_block_gns.c'],
              dependencies: [libgnunetutil_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetblockgroup_dep],
              include_directories: [incdir, configuration_inc],
              install:true,
              install_dir: get_option('libdir')/'gnunet')
shared_module('gnunet_plugin_rest_gns',
              ['plugin_rest_gns.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetgnsrecordjson_dep,
                             libgnunetgns_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')


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
executable ('gnunet-bcd',
            ['gnunet-bcd.c'],
            dependencies: [libgnunetgns_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetdht_dep,
                           libgnunetdns_dep,
                           mhd_dep,
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
executable ('gnunet-dns2gns',
            ['gnunet-dns2gns.c'],
            dependencies: [libgnunetgns_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetvpn_dep,
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


if have_nss
  subdir('nss')
endif
