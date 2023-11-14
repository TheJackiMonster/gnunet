libgnunetseti_src = ['seti_api.c']

gnunetserviceseti_src = ['gnunet-service-seti.c']

configure_file(input : 'seti.conf.in',
               output : 'seti.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetseti_src + gnunetserviceseti_src
    gnunet_src += 'seti/' + p
  endforeach
endif

libgnunetseti = library('gnunetseti',
        libgnunetseti_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
      install: true,
      install_dir: get_option('libdir'))
pkg.generate(libgnunetseti, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the set intersection service')
libgnunetseti_dep = declare_dependency(link_with : libgnunetseti)
executable ('gnunet-service-seti',
            gnunetserviceseti_src,
            dependencies: [libgnunetseti_dep,
                           libgnunetutil_dep,
                           m_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetcadet_dep,
                           libgnunetblock_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

