libgnunetcadet_src = [
    'cadet_api.c',
    'cadet_api_drop_message.c',
    'cadet_api_get_channel.c',
    'cadet_api_get_path.c',
    'cadet_api_list_peers.c',
    'cadet_api_list_tunnels.c',
    'cadet_api_helper.c',
]

gnunetcadet_src = ['gnunet-cadet.c']
gnunetservicecadet_src = [
    'gnunet-service-cadet.c',
    'gnunet-service-cadet_channel.c',
    'gnunet-service-cadet_connection.c',
    'gnunet-service-cadet_core.c',
    'gnunet-service-cadet_dht.c',
    'gnunet-service-cadet_hello.c',
    'gnunet-service-cadet_tunnels.c',
    'gnunet-service-cadet_paths.c',
    'gnunet-service-cadet_peer.c',
]

configure_file(
    input: 'cadet.conf.in',
    output: 'cadet.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

if get_option('monolith')
    foreach p : libgnunetcadet_src + gnunetservicecadet_src
        gnunet_src += 'cadet/' + p
    endforeach
endif

libgnunetcadet = library(
    'gnunetcadet',
    libgnunetcadet_src,
    soversion: solibversions['libgnunetcadet']['soversion'],
    version: solibversions['libgnunetcadet']['version'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetcadet_dep = declare_dependency(link_with: libgnunetcadet)
pkg.generate(
    libgnunetcadet,
    url: 'https://www.gnunet.org',
    description: 'API for multicast and multi-hop routing between GNUnet peers',
)

executable(
    'gnunet-service-cadet',
    gnunetservicecadet_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetcadet_dep,
        libgnunetutil_dep,
        m_dep,
        libgnunetcore_dep,
        libgnunetdht_dep,
        libgnunetstatistics_dep,
        libgnunettransportapplication_dep,
        libgnunetpeerstore_dep,
        libgnunethello_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

if false

    testcadetlocalmq = executable(
        'test_cadet_local_mq',
        ['test_cadet_local_mq.c'],
        dependencies: [
            libgnunetcadet_dep,
            libgnunettesting_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: false,
    )
    configure_file(
        input: 'test_cadet.conf',
        output: 'test_cadet.conf',
        configuration: cdata,
        install: false,
    )
    test(
        'test_cadet_local_mq',
        testcadetlocalmq,
        workdir: meson.current_build_dir(),
        suite: 'cadet',
    )


endif
