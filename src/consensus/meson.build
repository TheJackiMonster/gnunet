libgnunetconsensus_src = ['consensus_api.c']

gnunetserviceconsensus_src = ['gnunet-service-consensus.c']

configure_file(input : 'consensus.conf.in',
               output : 'consensus.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetconsensus_src + gnunetserviceconsensus_src
    gnunet_src += 'consensus/' + p
  endforeach
  subdir_done()
endif

libgnunetconsensus = shared_library('gnunetconsensus',
        libgnunetconsensus_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetconsensus, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the consensus service')
libgnunetarm_dep = declare_dependency(link_with : libgnunetarm)
libgnunetconsensus_dep = declare_dependency(link_with : libgnunetconsensus)
executable ('gnunet-service-consensus',
            gnunetserviceconsensus_src,
            dependencies: [libgnunetconsensus_dep,
                           libgnunetutil_dep,
                           libgnunetset_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

