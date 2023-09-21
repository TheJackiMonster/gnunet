libgnunetscalarproduct_src = ['scalarproduct_api.c']

gnunetservicescalarproduct_src = ['gnunet-service-scalarproduct.c',
                        'gnunet-service-scalarproduct_union.c',
                        'gnunet-service-scalarproduct_intersection.c',
                        'gnunet-service-scalarproduct_union_strata_estimator.c',
                        'ibf.c']

configure_file(input : 'scalarproduct.conf.in',
               output : 'scalarproduct.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetscalarproduct = library('gnunetscalarproduct',
          libgnunetscalarproduct_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetscalarproduct_dep = declare_dependency(link_with : libgnunetscalarproduct)
  executable ('gnunet-service-scalarproduct',
              gnunetservicescalarproduct_src,
              dependencies: [libgnunetscalarproduct_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetscalarproduct_src + gnunetservicescalarproduct_src
    gnunet_src += 'scalarproduct/' + p
  endforeach
endif
