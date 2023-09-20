libgnunetnt_src = ['nt.c']

if gnunet_monolith == false
  libgnunetnt = library('gnunetnt',
          libgnunetnt_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetnt_dep = declare_dependency(link_with : libgnunetnt)
else
  foreach p : libgnunetnt_src
    gnunet_src += 'nt/' + p
  endforeach
endif
