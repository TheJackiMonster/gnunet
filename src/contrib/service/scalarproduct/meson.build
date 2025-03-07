libgnunetscalarproduct_src = ['scalarproduct_api.c']

gnunetservicescalarproducta_src = ['gnunet-service-scalarproduct_alice.c']
gnunetservicescalarproductb_src = ['gnunet-service-scalarproduct_bob.c']
gnunetservicescalarproductecca_src = [
    'gnunet-service-scalarproduct-ecc_alice.c',
]
gnunetservicescalarproducteccb_src = ['gnunet-service-scalarproduct-ecc_bob.c']

configure_file(
    input: 'scalarproduct.conf.in',
    output: 'scalarproduct.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetscalarproduct_src + gnunetservicescalarproducta_src + gnunetservicescalarproductb_src + gnunetservicescalarproductecca_src + gnunetservicescalarproducteccb_src
        gnunet_src += 'scalarproduct/' + p
    endforeach
endif

libgnunetscalarproduct = library(
    'gnunetscalarproduct',
    libgnunetscalarproduct_src,
    soversion: '0',
    version: '0.0.0',
    dependencies: [libgnunetutil_dep, gcrypt_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
pkg.generate(
    libgnunetscalarproduct,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the scalarproduct service',
)
libgnunetscalarproduct_dep = declare_dependency(
    link_with: libgnunetscalarproduct,
)

executable(
    'gnunet-scalarproduct',
    ['gnunet-scalarproduct.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetscalarproduct_dep,
        libgnunetutil_dep,
        gcrypt_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

executable(
    'gnunet-service-scalarproduct-alice',
    gnunetservicescalarproducta_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetscalarproduct_dep,
        libgnunetutil_dep,
        gcrypt_dep,
        libgnunetseti_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-service-scalarproduct-bob',
    gnunetservicescalarproductb_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetscalarproduct_dep,
        libgnunetutil_dep,
        gcrypt_dep,
        libgnunetseti_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-service-scalarproduct-ecc-alice',
    gnunetservicescalarproductecca_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetscalarproduct_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        gcrypt_dep,
        sodium_dep,
        libgnunetseti_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-service-scalarproduct-ecc-bob',
    gnunetservicescalarproducteccb_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetscalarproduct_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        gcrypt_dep,
        sodium_dep,
        libgnunetseti_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

