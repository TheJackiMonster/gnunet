libgnunetblock_src = ['block.c']
libgnunetblockgroup_src = ['bg_bf.c']

if get_option('monolith')
  foreach p : libgnunetblock_src + libgnunetblockgroup_src
    gnunet_src += 'block/' + p
  endforeach
  subdir_done()
endif

libgnunetblock = library('gnunetblock',
        libgnunetblock_src,
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        soversion: '0.0.0',
        install_dir: get_option('libdir'))
libgnunetblock_dep = declare_dependency(link_with : libgnunetblock)
libgnunetblockgroup = library('gnunetblockgroup',
        libgnunetblockgroup_src,
        dependencies: [libgnunetutil_dep, libgnunetblock_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        soversion: '0.0.0',
        install_dir: get_option('libdir'))
libgnunetblockgroup_dep = declare_dependency(link_with : libgnunetblockgroup)

plugin_dep = [libgnunetutil_dep, libgnunetblock_dep, libgnunetblockgroup_dep]
shared_module('gnunet_plugin_block_test',
      ['plugin_block_test.c'],
      dependencies: plugin_dep,
      include_directories: [incdir, configuration_inc],
      install: true,
      install_dir: get_option('libdir'))
shared_module('gnunet_plugin_block_template',
      ['plugin_block_template.c'],
      dependencies: plugin_dep,
      include_directories: [incdir, configuration_inc],
      install: false,
      install_dir: get_option('libdir'))

