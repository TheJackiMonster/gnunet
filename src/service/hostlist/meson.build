gnunetdaemonhostlist_src = [
    'gnunet-daemon-hostlist.c',
    'gnunet-daemon-hostlist_server.c',
    'gnunet-daemon-hostlist_client.c',
]

configure_file(
    input: 'hostlist.conf',
    output: 'hostlist.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


executable(
    'gnunet-daemon-hostlist',
    gnunetdaemonhostlist_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetutil_dep,
        json_dep,
        libgnunetcore_dep,
        libgnunethello_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        mhd_dep,
        curl_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
