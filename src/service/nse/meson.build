libgnunetnse_src = ['nse_api.c']

gnunetservicense_src = ['gnunet-service-nse.c']

configure_file(
    input: 'nse.conf.in',
    output: 'nse.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetnse_src + gnunetservicense_src
        gnunet_src += 'nse/' + p
    endforeach
endif

libgnunetnse = library(
    'gnunetnse',
    libgnunetnse_src,
    soversion: solibversions['libgnunetnse']['soversion'],
    version: solibversions['libgnunetnse']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetnse_dep = declare_dependency(link_with: libgnunetnse)
pkg.generate(
    libgnunetnse,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the NSE service',
)

executable(
    'gnunet-service-nse',
    gnunetservicense_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnse_dep,
        libgnunetutil_dep,
        libgnunetcore_dep,
        m_dep,
        libgnunetstatistics_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

