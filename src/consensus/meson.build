libgnunetconsensus_src = ['consensus_api.c']

gnunetserviceconsensus_src = ['gnunet-service-consensus.c']

configure_file(input : 'consensus.conf.in',
               output : 'consensus.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith') == false
  libgnunetconsensus = library('gnunetconsensus',
          libgnunetconsensus_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
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
else
  foreach p : libgnunetconsensus_src + gnunetserviceconsensus_src
    gnunet_src += 'consensus/' + p
  endforeach
endif
