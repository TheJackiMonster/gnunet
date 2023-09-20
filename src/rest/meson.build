libgnunetrest_src = ['rest.c']

gnunetservicerest_src = ['gnunet-rest-server.c']


if gnunet_monolith == false
  libgnunetrest = library('gnunetrest',
          libgnunetrest_src,
          dependencies: [libgnunetutil_dep, mhd_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetrest_dep = declare_dependency(link_with : libgnunetrest)
  executable ('gnunet-rest-server',
              gnunetservicerest_src,
              dependencies: [libgnunetrest_dep, libgnunetutil_dep, mhd_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetrest_src + gnunetservicerest_src
    gnunet_src += 'rest/' + p
  endforeach
endif
