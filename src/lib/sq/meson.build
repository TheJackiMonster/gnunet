libgnunetsq_src = [
    'sq.c',
    'sq_exec.c',
    'sq_prepare.c',
    'sq_query_helper.c',
    'sq_result_helper.c',
]

libgnunetsq = library(
    'gnunetsq',
    libgnunetsq_src,
    soversion: solibversions['libgnunetsq']['soversion'],
    version: solibversions['libgnunetsq']['version'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, sqlite_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
pkg.generate(
    libgnunetsq,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the SQ service',
)
libgnunetsq_dep = declare_dependency(link_with: libgnunetsq)
testsq = executable(
    'test_sq',
    ['test_sq.c'],
    dependencies: [libgnunetutil_dep, sqlite_dep, libgnunetsq_dep],
    include_directories: [incdir, configuration_inc],
    build_by_default: false,
    install: false,
)
test('test_sq', testsq, workdir: meson.current_build_dir(), suite: ['sq'])


