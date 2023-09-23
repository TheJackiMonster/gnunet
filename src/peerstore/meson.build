libgnunetpeerstore_src = ['peerstore_api.c',
                          'peerstore_common.c']

gnunetservicepeerstore_src = ['gnunet-service-peerstore.c']

configure_file(input : 'peerstore.conf.in',
               output : 'peerstore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetpeerstore_src + gnunetservicepeerstore_src
    gnunet_src += 'peerstore/' + p
  endforeach
  subdir_done()
endif

libgnunetpeerstore = library('gnunetpeerstore',
        libgnunetpeerstore_src,
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetpeerstore, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the peerstore service')
libgnunetpeerstore_dep = declare_dependency(link_with : libgnunetpeerstore)

executable ('gnunet-service-peerstore',
            gnunetservicepeerstore_src,
            dependencies: [libgnunetpeerstore_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

