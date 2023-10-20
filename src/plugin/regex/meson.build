libgnunetregexblock_src = ['regex_block_lib.c']

libgnunetregexblock = library('gnunetregexblock',
        libgnunetregexblock_src,
        soversion: '1',
        version: '1.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetregexblock_dep = declare_dependency(link_with : libgnunetregexblock)

shared_module('gnunet_plugin_block_regex',
        ['plugin_block_regex.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetregexblock_dep,
                       libgnunetblock_dep,
                       libgnunetblockgroup_dep],
        include_directories: [incdir, configuration_inc],
              install:true,
              install_dir: get_option('libdir')/'gnunet')


