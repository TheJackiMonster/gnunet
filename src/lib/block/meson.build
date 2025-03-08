libgnunetblock_src = ['block.c']
libgnunetblockgroup_src = ['bg_bf.c']

libgnunetblock = library(
    'gnunetblock',
    libgnunetblock_src,
    soversion: solibversions['libgnunetblock']['soversion'],
    version: solibversions['libgnunetblock']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetblock_dep = declare_dependency(link_with: libgnunetblock)
pkg.generate(
    libgnunetblock,
    url: 'https://www.gnunet.org',
    description: 'Library for data block manipulation',
)

libgnunetblockgroup = library(
    'gnunetblockgroup',
    libgnunetblockgroup_src,
    soversion: solibversions['libgnunetblockgroup']['soversion'],
    version: solibversions['libgnunetblockgroup']['version'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunetblock_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetblockgroup_dep = declare_dependency(link_with: libgnunetblockgroup)
