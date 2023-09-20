libgnunetjson_src = ['json.c',
                    'json_generator.c',
                    'json_helper.c',
                    'json_mhd.c',
                    'json_pack.c']

if gnunet_monolith == false
  libgnunetjson = library('gnunetjson',
          libgnunetjson_src,
          dependencies: [libgnunetutil_dep, json_dep, mhd_dep, zlib_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetjson_dep = declare_dependency(link_with : libgnunetjson)
else
  foreach p : libgnunetjson_src + gnunetservicejson_src
    gnunet_src += 'json/' + p
  endforeach
endif
