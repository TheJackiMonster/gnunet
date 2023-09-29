libgnunetreclaim_src = ['reclaim_api.c',
                        'reclaim_attribute.c',
                        'reclaim_credential.c']
libgnunetdid_src = ['did_helper.c',
                    'did_core.c']

gnunetservicereclaim_src = ['gnunet-service-reclaim.c',
                        'gnunet-service-reclaim_tickets.c']

configure_file(input : 'reclaim.conf',
               output : 'reclaim.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetreclaim_src + gnunetservicereclaim_src
    gnunet_src += 'reclaim/' + p
  endforeach
  subdir_done()
endif

libgnunetreclaim = library('gnunetreclaim',
        libgnunetreclaim_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetreclaim_dep = declare_dependency(link_with : libgnunetreclaim)
pkg.generate(libgnunetreclaim, url: 'https://www.gnunet.org',
             description : 'Provides API to access reclaimID')

libgnunetdid = library('gnunetdid',
        libgnunetdid_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetnamestore_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetgns_dep,
                       json_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetdid_dep = declare_dependency(link_with : libgnunetdid)
pkg.generate(libgnunetdid, url: 'https://www.gnunet.org',
             description : 'Provides API to manipulate DID')

shared_module('gnunet_plugin_rest_reclaim',
              ['plugin_rest_reclaim.c', 'json_reclaim.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetidentity_dep,
                             libgnunetreclaim_dep,
                             libgnunetjson_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')


shared_module('gnunet_plugin_rest_openid_connect',
              ['plugin_rest_openid_connect.c', 'oidc_helper.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetreclaim_dep,
                             libgnunetidentity_dep,
                             libgnunetgns_dep,
                             libgnunetutil_dep,
                             jose_dep,
                             gcrypt_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')


executable ('gnunet-reclaim',
            'gnunet-reclaim.c',
            dependencies: [libgnunetreclaim_dep,
                           libgnunetidentity_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-did',
            'gnunet-did.c',
            dependencies: [libgnunetreclaim_dep,
                           libgnunetdid_dep,
                           libgnunetgns_dep,
                           libgnunetnamestore_dep,
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

