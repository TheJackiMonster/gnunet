libgnunetnatauto_src = ['nat_auto_api.c', 'nat_auto_api_test.c']

gnunetservicenatauto_src = ['gnunet-service-nat-auto.c']

configure_file(
    input: 'nat-auto.conf.in',
    output: 'nat-auto.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

if get_option('monolith')
    foreach p : libgnunetnatauto_src + gnunetservicenatauto_src
        gnunet_src += 'nat-auto/' + p
    endforeach
endif

libgnunetnatauto = library(
    'gnunetnatauto',
    libgnunetnatauto_src,
    soversion: solibversions['libgnunetnatauto']['soversion'],
    version: solibversions['libgnunetnatauto']['version'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunetnat_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetnatauto_dep = declare_dependency(link_with: libgnunetnatauto)

executable(
    'gnunet-service-nat-auto',
    gnunetservicenatauto_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnatauto_dep,
        libgnunetutil_dep,
        libgnunetnat_dep,
        libgnunetstatistics_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

