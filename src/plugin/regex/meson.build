libgnunetregexblock_src = ['regex_block_lib.c']

libgnunetregexblock = library(
    'gnunetregexblock',
    libgnunetregexblock_src,
    soversion: solibversions['libgnunetregexblock']['soversion'],
    version: solibversions['libgnunetregexblock']['version'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetregexblock_dep = declare_dependency(link_with: libgnunetregexblock)

shared_module(
    'gnunet_plugin_block_regex',
    ['plugin_block_regex.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetutil_dep,
        libgnunetregexblock_dep,
        libgnunetblock_dep,
        libgnunetblockgroup_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)


