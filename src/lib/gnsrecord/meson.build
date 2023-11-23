libgnunetgnsrecord_src = ['gnsrecord.c',
                          'gnsrecord_serialization.c',
                          'gnsrecord_crypto.c',
                          'gnsrecord_pow.c',
                          'gnsrecord_misc.c']
libgnunetgnsrecordjson_src = ['json_gnsrecord.c']

libgnunetgnsrecord = library('gnunetgnsrecord',
        libgnunetgnsrecord_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       sodium_dep,
                       gcrypt_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetgnsrecord_dep = declare_dependency(link_with : libgnunetgnsrecord)
pkg.generate(libgnunetgnsrecord, url: 'https://www.gnunet.org',
             description : 'Provides API for manipulating GNS records')


libgnunetgnsrecordjson = library('gnunetgnsrecordjson',
        libgnunetgnsrecordjson_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep, json_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetgnsrecordjson_dep = declare_dependency(link_with : libgnunetgnsrecordjson)

testgnsrecrd_perf_crypto = executable ('perf_gnsrecord_crypto',
          ['perf_gnsrecord_crypto.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
testgnsrecrd_test_crypto = executable ('test_gnsrecord_crypto',
          ['test_gnsrecord_crypto.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
testgnsrecrd_test_serialization = executable ('test_gnsrecord_serialization',
          ['test_gnsrecord_serialization.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
testgnsrecrd_test_tvs = executable ('test_gnsrecord_testvectors',
          ['test_gnsrecord_testvectors.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
testgnsrecrd_test_exp = executable ('test_gnsrecord_block_expiration',
          ['test_gnsrecord_block_expiration.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)

test('perf_gnsrecord_crypto', testgnsrecrd_perf_crypto,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord', 'perf'])
test('test_gnsrecord_crypto', testgnsrecrd_test_crypto,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord'])
test('test_gnsrecord_serialization', testgnsrecrd_test_serialization,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord'])
test('test_gnsrecord_block_expiration', testgnsrecrd_test_exp,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord'])
test('test_gnsrecord_serialization', testgnsrecrd_test_serialization,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord'])
test('test_gnsrecord_testvectors', testgnsrecrd_test_tvs,
   workdir: meson.current_build_dir(),
   suite: ['gnsrecord'])
