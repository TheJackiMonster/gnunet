libgnunetseti_src = ['seti_api.c']

gnunetserviceseti_src = ['gnunet-service-seti.c']


if get_option('monolith') == false
  libgnunetseti = library('gnunetseti',
          libgnunetseti_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetseti_dep = declare_dependency(link_with : libgnunetseti)
  executable ('gnunet-service-seti',
              gnunetserviceseti_src,
              dependencies: [libgnunetseti_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetseti_src + gnunetserviceseti_src
    gnunet_src += 'seti/' + p
  endforeach
endif
