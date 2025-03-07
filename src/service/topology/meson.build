gnunetdaemontopology_src = ['gnunet-daemon-topology.c']

configure_file(
    input: 'topology.conf',
    output: 'topology.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
# FIXME add daemon when new daemon macro is ported/ready for it.
    #foreach p : libgnunetfriends_src
    #  gnunet_src += 'topology/' + p
    #endforeach
endif

executable(
    'gnunet-daemon-topology',
    gnunetdaemontopology_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetutil_dep,
        libgnunetcore_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunettransportapplication_dep,
        libgnunethello_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

