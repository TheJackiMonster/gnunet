libgnunethello_src = ['hello-uri.c']

libgnunethello = library(
    'gnunethello',
    libgnunethello_src,
    soversion: solibversions['libgnunethello']['soversion'],
    version: solibversions['libgnunethello']['version'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunethello_dep = declare_dependency(link_with: libgnunethello)
pkg.generate(
    libgnunethello,
    url: 'https://www.gnunet.org',
    description: 'Helper library for handling GNUnet HELLO messages',
)


test_hello_uri = executable(
    'test_hello_uri',
    ['test_hello-uri.c'],
    dependencies: [libgnunethello_dep, libgnunetutil_dep, gcrypt_dep],
    include_directories: [incdir, configuration_inc],
    build_by_default: false,
    install: false,
)

test(
    'test_hello_uri',
    test_hello_uri,
    workdir: meson.current_build_dir(),
    suite: ['hello'],
)
