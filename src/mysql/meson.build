libgnunetmysq_src = ['mysql.c']

if get_option('monolith') == false
  libgnunetmysq = library('gnunetmysq',
          libgnunetmysq_src,
          dependencies: [libgnunetutil_dep, my_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetmysq_dep = declare_dependency(link_with : libgnunetmysq)
else
  foreach p : libgnunetmysq_src
    gnunet_src += 'mysql/' + p
  endforeach
endif
