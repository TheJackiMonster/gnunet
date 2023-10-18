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
               install_dir: get_option('bindir'))

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
              install_dir: get_option('libdir') / 'gnunet')


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

testgns = [
  'test_dns2gns',
  'test_gns_at_lookup',
  'test_gns_caa_lookup',
  'test_gns_config_lookup',
  'test_gns_delegated_lookup',
  'test_gns_dht_lookup',
  'test_gns_gns2dns_cname_lookup',
  'test_gns_gns2dns_lookup',
  'test_gns_gns2dns_zkey_lookup',
  'test_gns_ipv6_lookup',
  'test_gns_lookup',
  'test_gns_multiple_record_lookup',
  'test_gns_mx_lookup',
  'test_gns_quickupdate',
  'test_gns_redirect_lookup',
  'test_gns_rel_expiration',
  'test_gns_revocation',
  'test_gns_soa_lookup',
  'test_gns_txt_lookup',
  'test_gns_zkey_lookup',
  'test_plugin_rest_gns',
]

testconfigs = [
  'test_dns2gns.conf',
  'test_gns_defaults.conf',
  'test_gns_lookup.conf',
  'test_gns_lookup_peer1.conf',
  'test_gns_lookup_peer2.conf',
  'test_gns_proxy.conf',
  'test_gns_simple_lookup.conf'
]

foreach f : testconfigs
  configure_file(input: f, output: f, copy: true)
endforeach

foreach t : testgns

  test_filename = t + '.sh'
  test_file = configure_file(input : test_filename,
               output : test_filename,
               copy: true)

  test(t, test_file, suite: 'gns', workdir: meson.current_build_dir(), is_parallel: false)
endforeach
