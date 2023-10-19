gnunetserviceresolver_src = ['gnunet-service-resolver.c']

configure_file(input : 'resolver.conf.in',
               output : 'resolver.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : gnunetserviceresolver_src
    gnunet_src += 'util/' + p
  endforeach
endif

executable ('gnunet-service-resolver',
            gnunetserviceresolver_src,
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
