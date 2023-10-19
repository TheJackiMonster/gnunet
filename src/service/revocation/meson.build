libgnunetrevocation_src = ['revocation_api.c']

gnunetservicerevocation_src = ['gnunet-service-revocation.c']

configure_file(input : 'revocation.conf.in',
               output : 'revocation.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetrevocation_src + gnunetservicerevocation_src
    gnunet_src += 'revocation/' + p
  endforeach
endif

libgnunetrevocation = library('gnunetrevocation',
        libgnunetrevocation_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetrevocation_dep = declare_dependency(link_with : libgnunetrevocation)
pkg.generate(libgnunetrevocation, url: 'https://www.gnunet.org',
             description : 'Provides API to perform key revocation in GNUnet')

executable ('gnunet-service-revocation',
            gnunetservicerevocation_src,
            dependencies: [libgnunetrevocation_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetsetu_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

