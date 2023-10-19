shared_module('gnunet_plugin_rest_reclaim',
              ['plugin_rest_reclaim.c', 'json_reclaim.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetidentity_dep,
                             libgnunetreclaim_dep,
                             libgnunetjson_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')

shared_module('gnunet_plugin_rest_openid_connect',
              ['plugin_rest_openid_connect.c', 'oidc_helper.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetreclaim_dep,
                             libgnunetidentity_dep,
                             libgnunetgns_dep,
                             libgnunetutil_dep,
                             jose_dep,
                             gcrypt_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet')


