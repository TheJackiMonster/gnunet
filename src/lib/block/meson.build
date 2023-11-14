libgnunetblock_src = ['block.c']
libgnunetblockgroup_src = ['bg_bf.c']

libgnunetblock = library('gnunetblock',
        libgnunetblock_src,
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        version: '0.0.0',
        soversion: '0',
        install_dir: get_option('libdir'))
libgnunetblock_dep = declare_dependency(link_with : libgnunetblock)
pkg.generate(libgnunetblock, url: 'https://www.gnunet.org',
             description : 'Library for data block manipulation')

libgnunetblockgroup = library('gnunetblockgroup',
        libgnunetblockgroup_src,
        dependencies: [libgnunetutil_dep, libgnunetblock_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        version: '0.0.0',
        soversion: '0',
        install_dir: get_option('libdir'))
libgnunetblockgroup_dep = declare_dependency(link_with : libgnunetblockgroup)
