libgnunetjson_src = ['json.c',
                    'json_generator.c',
                    'json_helper.c',
                    'json_mhd.c',
                    'json_pack.c']

libgnunetjson = library('gnunetjson',
        libgnunetjson_src,
        soversion: '2',
        version: '2.0.0',
        dependencies: [libgnunetutil_dep, json_dep, mhd_dep, zlib_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetjson_dep = declare_dependency(link_with : libgnunetjson)
pkg.generate(libgnunetjson, url: 'https://www.gnunet.org',
             description : 'Library for JSON de/serialization')

testjson = executable ('test_json',
          ['test_json.c'],
          dependencies: [libgnunetutil_dep,
                         json_dep,
                         libgnunetjson_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
testjson_mhd = executable ('test_json_mhd',
          ['test_json_mhd.c'],
          dependencies: [libgnunetutil_dep,
                         json_dep,
                         mhd_dep,
                         curl_dep,
                         zlib_dep,
                         libgnunetjson_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
test('test_json', testjson,
   workdir: meson.current_build_dir(),
   suite: ['json'])
test('test_json_mhd', testjson_mhd,
   workdir: meson.current_build_dir(),
   suite: ['json'])

