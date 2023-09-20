libgnunetconsensus_src = ['consensus_api.c']

gnunetserviceconsensus_src = ['gnunet-service-consensus.c']


if gnunet_monolith == false
  libgnunetconsensus = library('gnunetconsensus',
          libgnunetconsensus_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetconsensus_dep = declare_dependency(link_with : libgnunetconsensus)
  executable ('gnunet-service-consensus',
              gnunetserviceconsensus_src,
              dependencies: [libgnunetconsensus_dep,
                             libgnunetutil_dep,
                             libgnunetset_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetconsensus_src + gnunetserviceconsensus_src
    gnunet_src += 'consensus/' + p
  endforeach
endif
