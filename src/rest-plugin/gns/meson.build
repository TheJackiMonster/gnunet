shared_module('gnunet_plugin_rest_gns',
              ['plugin_rest_gns.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetgnsrecordjson_dep,
                             libgnunetgns_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')

