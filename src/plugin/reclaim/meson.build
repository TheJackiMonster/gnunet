shared_module(
    'gnunet_plugin_gnsrecord_reclaim',
    ['plugin_gnsrecord_reclaim.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

shared_module(
    'gnunet_plugin_reclaim_attribute_basic',
    ['plugin_reclaim_attribute_basic.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetjson_dep, libgnunetutil_dep, json_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)
shared_module(
    'gnunet_plugin_reclaim_credential_jwt',
    [
        'plugin_reclaim_credential_jwt.c',
        '../../service/reclaim/reclaim_attribute.c',
        '../../service/reclaim/reclaim_credential.c',
    ],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetjson_dep, libgnunetutil_dep, json_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

