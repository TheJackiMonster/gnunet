libgnunetmhd_src = ['mhd_upload.c']

libgnunetmhd = library('gnunetmhd',
        libgnunetmhd_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, mhd_dep, json_dep, zlib_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetmhd_dep = declare_dependency(link_with : libgnunetmhd)
pkg.generate(libgnunetmhd, url: 'https://www.gnunet.org',
             description : 'Library for MHD upload parsing')

testmhd = executable ('test_mhd',
          ['test_mhd.c'],
          dependencies: [libgnunetutil_dep,
                         mhd_dep,
                         json_dep,
                         libgnunetmhd_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
test('test_mhd', testmhd,
   workdir: meson.current_build_dir(),
   suite: ['mhd'])
