libgnunetblock_src = ['block.c']
libgnunetblockgroup_src = ['bg_bf.c']

if gnunet_monolith == false
  libgnunetblock = library('gnunetblock',
          libgnunetblock_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetblock_dep = declare_dependency(link_with : libgnunetblock)
  libgnunetblockgroup = library('gnunetblockgroup',
          libgnunetblockgroup_src,
          dependencies: [libgnunetutil_dep, libgnunetblock_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetblockgroup_dep = declare_dependency(link_with : libgnunetblockgroup)
else
  foreach p : libgnunetblock_src + libgnunetblockgroup_src
    gnunet_src += 'block/' + p
  endforeach
endif
