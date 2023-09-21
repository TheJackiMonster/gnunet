libgnunetblock_src = ['block.c']
libgnunetblockgroup_src = ['bg_bf.c']

if get_option('monolith') == false
  libgnunetblock = library('gnunetblock',
          libgnunetblock_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetblock_dep = declare_dependency(link_with : libgnunetblock)
  libgnunetblockgroup = library('gnunetblockgroup',
          libgnunetblockgroup_src,
          dependencies: [libgnunetutil_dep, libgnunetblock_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetblockgroup_dep = declare_dependency(link_with : libgnunetblockgroup)
else
  foreach p : libgnunetblock_src + libgnunetblockgroup_src
    gnunet_src += 'block/' + p
  endforeach
endif
