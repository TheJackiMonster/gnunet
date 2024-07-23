libgnunetabd_src = ['abd_api.c',
                        'abd_serialization.c',
                        'delegate_misc.c']
gnunetserviceabd_src = ['gnunet-service-abd.c']

configure_file(input : 'abd.conf.in',
               output : 'abd.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetabd_src + gnunetserviceabd_src
    gnunet_src += 'abd/' + p
  endforeach
endif

libgnunetabd = library('gnunetabd',
        libgnunetabd_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetabd_dep = declare_dependency(link_with : libgnunetabd)
pkg.generate(libgnunetabd, url: 'https://www.gnunet.org',
             description : 'Attribute-based delegation through GNS')

executable ('gnunet-service-abd',
            gnunetserviceabd_src,
            dependencies: [libgnunetabd_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetgns_dep,
                           libgnunetidentity_dep,
                           libgnunetnamestore_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-abd',
            'gnunet-abd.c',
            dependencies: [libgnunetabd_dep,
                           libgnunetidentity_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetnamestore_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

