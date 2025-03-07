libgnunetset_src = ['set_api.c']

gnunetserviceset_src = [
    'gnunet-service-set.c',
    'gnunet-service-set_union.c',
    'gnunet-service-set_intersection.c',
    'gnunet-service-set_union_strata_estimator.c',
    'ibf.c',
]

configure_file(
    input: 'set.conf.in',
    output: 'set.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


libgnunetset = library(
    'gnunetset',
    libgnunetset_src,
    soversion: '0',
    version: '0.0.0',
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
pkg.generate(
    libgnunetset,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the set service',
)
libgnunetset_dep = declare_dependency(link_with: libgnunetset)
shared_module(
    'gnunet_plugin_block_set_test',
    ['plugin_block_set_test.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)
executable(
    'gnunet-service-set',
    gnunetserviceset_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetset_dep,
        libgnunetutil_dep,
        m_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

