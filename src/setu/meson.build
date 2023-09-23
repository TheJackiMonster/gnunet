libgnunetsetu_src = ['setu_api.c']

gnunetservicesetu_src = ['gnunet-service-setu.c',
                         'ibf.c',
                         'gnunet-service-setu_strata_estimator.c']

configure_file(input : 'setu.conf.in',
               output : 'setu.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetsetu_src + gnunetservicesetu_src
    gnunet_src += 'setu/' + p
  endforeach
  subdir_done()
endif

libgnunetsetu = library('gnunetsetu',
        libgnunetsetu_src,
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetsetu, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the set union service')
libgnunetsetu_dep = declare_dependency(link_with : libgnunetsetu)
executable ('gnunet-service-setu',
            gnunetservicesetu_src,
            dependencies: [libgnunetsetu_dep,
                           libgnunetutil_dep,
                           m_dep,
                           libgnunetstatistics_dep,
                           libgnunetcore_dep,
                           libgnunetcadet_dep,
                           libgnunetblock_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

