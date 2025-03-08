libgnunetnat_src = ['nat_api.c', 'nat_api_stun.c']

gnunetservicenat_src = [
    'gnunet-service-nat.c',
    'gnunet-service-nat.c',
    'gnunet-service-nat_externalip.c',
    'gnunet-service-nat_stun.c',
    'gnunet-service-nat_mini.c',
    'gnunet-service-nat_helper.c',
]

configure_file(
    input: 'nat.conf.in',
    output: 'nat.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetnat_src + gnunetservicenat_src
        gnunet_src += 'nat/' + p
    endforeach
endif

libgnunetnat = library(
    'gnunetnat',
    libgnunetnat_src,
    soversion: solibversions['libgnunetnat']['soversion'],
    version: solibversions['libgnunetnat']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetnat_dep = declare_dependency(link_with: libgnunetnat)
pkg.generate(
    libgnunetnat,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the NAT service',
)
libgnunetnat = library(
    'gnunetnatnew',
    ['nat_api.c', 'nat_api_stun.c'],
    soversion: solibversions['libgnunetnat']['soversion'],
    version: solibversions['libgnunetnat']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetnat_dep = declare_dependency(link_with: libgnunetnat)

executable(
    'gnunet-service-nat',
    gnunetservicenat_src,
    install_rpath: rpath_option,
    dependencies: [libgnunetnat_dep, libgnunetutil_dep, libgnunetstatistics_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-helper-nat-server',
    ['gnunet-helper-nat-server.c'],
    install_rpath: rpath_option,
    dependencies: [libgnunetnat_dep, libgnunetutil_dep, libgnunetstatistics_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-helper-nat-client',
    ['gnunet-helper-nat-client.c'],
    install_rpath: rpath_option,
    dependencies: [libgnunetnat_dep, libgnunetutil_dep, libgnunetstatistics_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

