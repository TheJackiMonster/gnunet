libgnunetstatistics_src = ['statistics_api.c']

gnunetservicestatistics_src = ['gnunet-service-statistics.c']

configure_file(input : 'statistics.conf.in',
               output : 'statistics.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetstatistics = library('gnunetstatistics',
          libgnunetstatistics_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetstatistics_dep = declare_dependency(link_with : libgnunetstatistics)
  executable ('gnunet-service-statistics',
              gnunetservicestatistics_src,
              dependencies: [libgnunetstatistics_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetstatistics_src + gnunetservicestatistics_src
    gnunet_src += 'statistics/' + p
  endforeach
endif
