libgnunetset_src = ['set_api.c']

gnunetserviceset_src = ['gnunet-service-set.c',
                        'gnunet-service-set_union.c',
                        'gnunet-service-set_intersection.c',
                        'gnunet-service-set_union_strata_estimator.c',
                        'ibf.c']


if gnunet_monolith == false
  libgnunetset = library('gnunetset',
          libgnunetset_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetset_dep = declare_dependency(link_with : libgnunetset)
  executable ('gnunet-service-set',
              gnunetserviceset_src,
              dependencies: [libgnunetset_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetset_src + gnunetserviceset_src
    gnunet_src += 'set/' + p
  endforeach
endif
