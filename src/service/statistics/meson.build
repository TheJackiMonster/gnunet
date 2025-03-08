libgnunetstatistics_src = ['statistics_api.c']

gnunetservicestatistics_src = ['gnunet-service-statistics.c']

configure_file(
    input: 'statistics.conf.in',
    output: 'statistics.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetstatistics_src + gnunetservicestatistics_src
        gnunet_src += 'statistics/' + p
    endforeach
endif

libgnunetstatistics = library(
    'gnunetstatistics',
    libgnunetstatistics_src,
    soversion: solibversions['libgnunetstatistics']['soversion'],
    version: solibversions['libgnunetstatistics']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetstatistics_dep = declare_dependency(link_with: libgnunetstatistics)
pkg.generate(
    libgnunetstatistics,
    url: 'https://www.gnunet.org',
    description: 'Provides API of GNUnet statistics service',
)

executable(
    'gnunet-service-statistics',
    gnunetservicestatistics_src,
    install_rpath: rpath_option,
    dependencies: [libgnunetstatistics_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
