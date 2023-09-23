libgnunetjson_src = ['json.c',
                    'json_generator.c',
                    'json_helper.c',
                    'json_mhd.c',
                    'json_pack.c']

if get_option('monolith')
  foreach p : libgnunetjson_src
    gnunet_src += 'json/' + p
  endforeach
  subdir_done()
endif

libgnunetjson = library('gnunetjson',
        libgnunetjson_src,
        soversion: '0.0.0',
        dependencies: [libgnunetutil_dep, json_dep, mhd_dep, zlib_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetjson_dep = declare_dependency(link_with : libgnunetjson)
pkg.generate(libgnunetjson, url: 'https://www.gnunet.org',
             description : 'Library for JSON de/serialization')

