libgnunetnse_src = ['nse_api.c']

gnunetservicense_src = ['gnunet-service-nse.c']

if get_option('monolith') == false
  libgnunetnse = library('gnunetnse',
          libgnunetnse_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetnse_dep = declare_dependency(link_with : libgnunetnse)
  executable ('gnunet-service-nse',
              gnunetservicense_src,
              dependencies: [libgnunetnse_dep, libgnunetutil_dep,
                             libgnunetcore_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetnse_src + gnunetservicense_src
    gnunet_src += 'nse/' + p
  endforeach
endif
