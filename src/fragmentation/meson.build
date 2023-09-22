libgnunetfragmentation_src = ['fragmentation.c',
                              'defragmentation.c']

if get_option('monolith') == false
  libgnunetfragmentation = library('gnunetfragmentation',
          libgnunetfragmentation_src,
          dependencies: [m_dep, libgnunetutil_dep, libgnunetstatistics_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetfragmentation_dep = declare_dependency(link_with : libgnunetfragmentation)
else
  foreach p : libgnunetfragmentation_src
    gnunet_src += 'fragmentation/' + p
  endforeach
endif
