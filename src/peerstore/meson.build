libgnunetpeerstore_src = ['peerstore_api.c',
                          'peerstore_common.c']

gnunetservicepeerstore_src = ['gnunet-service-peerstore.c']

configure_file(input : 'peerstore.conf.in',
               output : 'peerstore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetpeerstore = library('gnunetpeerstore',
          libgnunetpeerstore_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetpeerstore_dep = declare_dependency(link_with : libgnunetpeerstore)
  executable ('gnunet-service-peerstore',
              gnunetservicepeerstore_src,
              dependencies: [libgnunetpeerstore_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetpeerstore_src + gnunetservicepeerstore_src
    gnunet_src += 'peerstore/' + p
  endforeach
endif
