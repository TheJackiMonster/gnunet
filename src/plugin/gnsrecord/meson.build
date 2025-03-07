shared_module(
    'gnunet_plugin_gnsrecord_dns',
    ['plugin_gnsrecord_dns.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)
