libgnunetrest_src = ['rest.c']

gnunetservicerest_src = ['gnunet-rest-server.c',
                         'config_plugin.c',
                         'copying_plugin.c',
                         'identity_plugin.c',
                         'namestore_plugin.c',
                         'gns_plugin.c',
                         'json_reclaim.c',
                         'reclaim_plugin.c',
                         ]

if jose_dep.found()
  gnunetservicerest_src += ['oidc_helper.c', 'openid_plugin.c']
endif

configure_file(input : 'rest.conf',
               output : 'rest.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetrest_src + gnunetservicerest_src
    gnunet_src += 'rest/' + p
  endforeach
endif


libgnunetrest = library('gnunetrest',
        libgnunetrest_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, mhd_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetrest, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the REST service')
libgnunetrest_dep = declare_dependency(link_with : libgnunetrest)

executable ('gnunet-rest-server',
            gnunetservicerest_src,
            dependencies: [libgnunetrest_dep,
                           libgnunetutil_dep,
                           libgnunetidentity_dep,
                           libgnunetgns_dep,
                           libgnunetreclaim_dep,
                           libgnunetnamestore_dep,
                           libgnunetjson_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetgnsrecordjson_dep,
                           json_dep,
                           jose_dep,
                           gcrypt_dep,
                           mhd_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

