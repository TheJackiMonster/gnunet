libgnunettestbed_src = ['testbed.c']

libgnunettestbed = library(
    'gnunettestbed',
    libgnunettestbed_src,
    soversion: solibversions['libgnunettestbed']['soversion'],
    version: solibversions['libgnunettestbed']['version'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
pkg.generate(
    libgnunettestbed,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the testbed functions',
)
libgnunettestbed_dep = declare_dependency(link_with: libgnunettestbed)

executable(
    'gnunet-testbed',
    'gnunet-testbed.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunettestbed_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

libgnunettestingtestbed = library(
    'gnunettestingtestbed',
    ['testbed_api_cmd_system_create.c', 'testing_testbed_traits.c'],
    soversion: solibversions['libgnunettestingtestbed']['soversion'],
    version: solibversions['libgnunettestingtestbed']['version'],
    dependencies: [
        libgnunetutil_dep,
        libgnunettesting_dep,
        libgnunettestbed_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: get_option('prefix') / get_option('libdir'),
)
libgnunettestingtestbed_dep = declare_dependency(
    link_with: libgnunettestingtestbed,
)
