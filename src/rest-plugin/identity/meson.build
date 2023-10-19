shared_module('gnunet_plugin_rest_identity',
              ['plugin_rest_identity.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetidentity_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')

