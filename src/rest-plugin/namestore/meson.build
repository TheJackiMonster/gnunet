shared_module('gnunet_plugin_rest_namestore',
              ['plugin_rest_namestore.c'],
              dependencies: [
                             libgnunetrest_dep,
                             libgnunetgnsrecordjson_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetjson_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')

