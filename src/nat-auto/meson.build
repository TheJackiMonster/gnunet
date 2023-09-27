libgnunetnatauto_src = ['nat_auto_api.c',
                        'nat_auto_api_test.c']

gnunetservicenatauto_src = ['gnunet-nat-server.c']

configure_file(input : 'nat-auto.conf.in',
               output : 'nat-auto.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetnatauto_src + gnunetservicenatauto_src
    gnunet_src += 'nat-auto/' + p
  endforeach
  subdir_done()
endif

libgnunetnatauto = library('gnunetnatauto',
        libgnunetnatauto_src,
        dependencies: [libgnunetutil_dep, libgnunetnat_dep],
        include_directories: [incdir, configuration_inc])
libgnunetnatauto_dep = declare_dependency(link_with : libgnunetnatauto)

executable ('gnunet-nat-auto',
            ['gnunet-nat-auto.c'],
            dependencies: [libgnunetnatauto_dep, libgnunetutil_dep,
                           libgnunetnat_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-nat-server',
            gnunetservicenatauto_src,
            dependencies: [libgnunetnatauto_dep, libgnunetutil_dep, libgnunetnat_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

