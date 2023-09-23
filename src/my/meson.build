libgnunetmy_src = ['my.c',
                   'my_query_helper.c',
                   'my_result_helper.c']

if get_option('monolith') == false
  libgnunetmy = library('gnunetmy',
          libgnunetmy_src,
          dependencies: [libgnunetutil_dep, libgnunetmysq_dep, my_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetmy_dep = declare_dependency(link_with : libgnunetmy)
else
  foreach p : libgnunetmy_src
    gnunet_src += 'my/' + p
  endforeach
endif
