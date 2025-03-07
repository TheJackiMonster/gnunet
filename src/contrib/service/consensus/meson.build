libgnunetconsensus_src = ['consensus_api.c']

gnunetserviceconsensus_src = ['gnunet-service-consensus.c']

configure_file(
    input: 'consensus.conf.in',
    output: 'consensus.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

# FIXME needs new seti/setu
if get_option('monolith')
#foreach p : libgnunetconsensus_src + gnunetserviceconsensus_src
    #  gnunet_src += 'consensus/' + p
    #endforeach
endif

libgnunetconsensus = shared_library(
    'gnunetconsensus',
    libgnunetconsensus_src,
    soversion: '0',
    version: '0.0.0',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
pkg.generate(
    libgnunetconsensus,
    url: 'https://www.gnunet.org',
    description: 'Provides API for accessing the consensus service',
)
libgnunetarm_dep = declare_dependency(link_with: libgnunetarm)
libgnunetconsensus_dep = declare_dependency(link_with: libgnunetconsensus)

shared_module(
    'gnunet_plugin_block_consensus',
    ['plugin_block_consensus.c'],
    dependencies: [libgnunetutil_dep, libgnunetblock_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet',
)

executable(
    'gnunet-service-consensus',
    gnunetserviceconsensus_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetconsensus_dep,
        libgnunetutil_dep,
        libgnunetset_dep,
        libgnunetstatistics_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

# FIXME do we need evil stuff and ENABLE_MALICIOUS?
if false

    testconsensusapi = executable(
        'test_consensus_api',
        ['test_consensus_api.c'],
        dependencies: [
            libgnunetconsensus_dep,
            libgnunetutil_dep,
            libgnunettesting_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: false,
    )

    configure_file(
        input: 'test_consensus.conf',
        output: 'test_consensus.conf',
        configuration: cdata,
        install: false,
    )

    test(
        'test_consensus_api',
        testconsensusapi,
        workdir: meson.current_build_dir(),
        suite: ['consensus', 'contrib'],
    )

endif
