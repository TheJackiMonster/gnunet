libgnunetfragmentation_src = ['fragmentation.c',
                              'defragmentation.c']

if gnunet_monolith == false
  libgnunetfragmentation = library('gnunetfragmentation',
          libgnunetfragmentation_src,
          dependencies: [libgnunetutil_dep, libgnunetstatistics_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetfragmentation_dep = declare_dependency(link_with : libgnunetfragmentation)
else
  foreach p : libgnunetfragmentation_src
    gnunet_src += 'fragmentation/' + p
  endforeach
endif
