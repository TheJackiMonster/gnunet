libgnunetnatauto_src = ['nat_auto_api.c',
                        'nat_auto_api_test.c']

gnunetservicenatauto_src = ['gnunet-nat-server.c']


if get_option('monolith') == false
  libgnunetnatauto = library('gnunetnatauto',
          libgnunetnatauto_src,
          dependencies: [libgnunetutil_dep, libgnunetnat_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetnatauto_dep = declare_dependency(link_with : libgnunetnatauto)
  executable ('gnunet-nat-server',
              gnunetservicenatauto_src,
              dependencies: [libgnunetnatauto_dep, libgnunetutil_dep, libgnunetnat_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetnatauto_src + gnunetservicenatauto_src
    gnunet_src += 'nat-auto/' + p
  endforeach
endif
