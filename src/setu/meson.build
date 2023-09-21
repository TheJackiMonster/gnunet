libgnunetsetu_src = ['setu_api.c']

gnunetservicesetu_src = ['gnunet-service-setu.c',
                         'ibf.c',
                         'gnunet-service-setu_strata_estimator.c']


if get_option('monolith') == false
  libgnunetsetu = library('gnunetsetu',
          libgnunetsetu_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetsetu_dep = declare_dependency(link_with : libgnunetsetu)
  executable ('gnunet-service-setu',
              gnunetservicesetu_src,
              dependencies: [libgnunetsetu_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetsetu_src + gnunetservicesetu_src
    gnunet_src += 'setu/' + p
  endforeach
endif
