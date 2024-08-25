libgnunetidentity_src = ['identity_api.c',
                         'identity_api_lookup.c',
                         'identity_api_suffix_lookup.c']

gnunetserviceidentity_src = ['gnunet-service-identity.c']

configure_file(input : 'identity.conf',
               output : 'identity.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetidentity_src + gnunetserviceidentity_src
    gnunet_src += 'identity/' + p
  endforeach
endif

libgnunetidentity = library('gnunetidentity',
        libgnunetidentity_src,
        soversion: '1',
        version: '1.0.0',
        dependencies: [libgnunetutil_dep, sodium_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetidentity_dep = declare_dependency(link_with : libgnunetidentity)
pkg.generate(libgnunetidentity, url: 'https://www.gnunet.org',
             description : 'API to access and organize private keys of the user egos')

executable ('gnunet-service-identity',
            gnunetserviceidentity_src,
            dependencies: [libgnunetidentity_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

