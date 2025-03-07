libgnunetjson_src = [
    'json.c',
    'json_generator.c',
    'json_helper.c',
    'json_pack.c',
]

libgnunetjson = library(
    'gnunetjson',
    libgnunetjson_src,
    soversion: solibversions['libgnunetjson']['soversion'],
    version: solibversions['libgnunetjson']['version'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep, json_dep, zlib_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetjson_dep = declare_dependency(link_with: libgnunetjson)
pkg.generate(
    libgnunetjson,
    url: 'https://www.gnunet.org',
    description: 'Library for JSON de/serialization',
)

testjson = executable(
    'test_json',
    ['test_json.c'],
    dependencies: [libgnunetutil_dep, json_dep, libgnunetjson_dep],
    include_directories: [incdir, configuration_inc],
    build_by_default: false,
    install: false,
)
test('test_json', testjson, workdir: meson.current_build_dir(), suite: ['json'])
