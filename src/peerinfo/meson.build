libgnunetpeerinfo_src = ['peerinfo_api.c',
                         'peerinfo_api_notify.c']

gnunetservicepeerinfo_src = ['gnunet-service-peerinfo.c']

configure_file(input : 'peerinfo.conf.in',
               output : 'peerinfo.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetpeerinfo_src + gnunetservicepeerinfo_src
    gnunet_src += 'peerinfo/' + p
  endforeach
  subdir_done()
endif

libgnunetpeerinfo = library('gnunetpeerinfo',
        libgnunetpeerinfo_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetpeerinfo_dep = declare_dependency(link_with : libgnunetpeerinfo)
pkg.generate(libgnunetpeerinfo, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the peerinfo service')

executable ('gnunet-service-peerinfo',
            gnunetservicepeerinfo_src,
            dependencies: [libgnunetpeerinfo_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunethello_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

