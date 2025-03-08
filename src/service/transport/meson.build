libgnunettransportapplication_src = ['transport_api_application.c']
libgnunettransportcore_src = ['transport_api_core.c']
libgnunettransportcommunicator_src = ['transport_api_communication.c']
libgnunettransportmonitor_src = ['transport_api_monitor.c']

gnunetservicetransport_src = ['gnunet-service-transport.c']
gnunetcommunicatortcp_src = ['gnunet-communicator-tcp.c']
gnunetcommunicatorudp_src = ['gnunet-communicator-udp.c']
gnunetcommunicatorhttp3_src = ['gnunet-communicator-http3.c']
gnunetcommunicatorquic_src = ['gnunet-communicator-quic.c']
gnunetcommunicatorunix_src = ['gnunet-communicator-unix.c']
configure_file(
    input: 'transport.conf.in',
    output: 'transport.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

configure_file(
    input: 'gnunet-transport-certificate-creation.in',
    output: 'gnunet-transport-certificate-creation',
    configuration: cdata,
    install: true,
    install_mode: 'rwxr-xr-x',
    install_dir: get_option('bindir'),
)

if get_option('monolith')
    foreach p : libgnunettransportapplication_src + libgnunettransportcore_src + libgnunettransportcommunicator_src + libgnunettransportmonitor_src + gnunetservicetransport_src
        gnunet_src += 'transport/' + p
    endforeach
endif

libgnunettransportapplication = library(
    'gnunettransportapplication',
    libgnunettransportapplication_src,
    soversion: solibversions['libgnunettransportapplication']['soversion'],
    version: solibversions['libgnunettransportapplication']['version'],
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: rpath_option,
)
pkg.generate(
    libgnunettransportapplication,
    url: 'https://www.gnunet.org',
    description: 'Provides application APIs for accessing the transport service',
)
libgnunettransportapplication_dep = declare_dependency(
    link_with: libgnunettransportapplication,
)

libgnunettransportcore = library(
    'gnunettransportcore',
    libgnunettransportcore_src,
    soversion: solibversions['libgnunettransportcore']['soversion'],
    version: solibversions['libgnunettransportcore']['version'],
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: rpath_option,
)
pkg.generate(
    libgnunettransportcore,
    url: 'https://www.gnunet.org',
    description: 'Provides core API for accessing the transport service',
)
libgnunettransportcore_dep = declare_dependency(
    link_with: libgnunettransportcore,
)

libgnunettransportcommunicator = library(
    'gnunettransportcommunicator',
    libgnunettransportcommunicator_src,
    soversion: solibversions['libgnunettransportcommunicator']['soversion'],
    version: solibversions['libgnunettransportcommunicator']['version'],
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: rpath_option,
)
pkg.generate(
    libgnunettransportcommunicator,
    url: 'https://www.gnunet.org',
    description: 'Provides communicator API for accessing the transport service',
)
libgnunettransportcommunicator_dep = declare_dependency(
    link_with: libgnunettransportcommunicator,
)

libgnunettransportmonitor = library(
    'gnunettransportmonitor',
    libgnunettransportmonitor_src,
    soversion: solibversions['libgnunettransportmonitor']['soversion'],
    version: solibversions['libgnunettransportmonitor']['version'],
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: rpath_option,
)
pkg.generate(
    libgnunettransportmonitor,
    url: 'https://www.gnunet.org',
    description: 'Provides monitor API for accessing the transport service',
)
libgnunettransportmonitor_dep = declare_dependency(
    link_with: libgnunettransportmonitor,
)

libgnunettestingtransport = library(
    'gnunettestingtransport',
    ['testing_transport_traits.c', 'transport-testing-communicator.c'],
    soversion: solibversions['libgnunettestingtransport']['soversion'],
    version: solibversions['libgnunettestingtransport']['version'],
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportcore_dep,
        libgnunettransportapplication_dep,
        libgnunetpeerstore_dep,
        libgnunettesting_dep,
        libgnunethello_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
    install_rpath: rpath_option,
)
libgnunettestingtransport_dep = declare_dependency(
    link_with: libgnunettestingtransport,
)

executable(
    'gnunet-service-transport',
    gnunetservicetransport_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunettransportcommunicator_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetnat_dep,
        gcrypt_dep,
        m_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

executable(
    'gnunet-communicator-unix',
    gnunetcommunicatorunix_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunettransportcommunicator_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunetnat_dep,
        gcrypt_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-communicator-udp',
    gnunetcommunicatorudp_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunettransportcommunicator_dep,
        libgnunettransportapplication_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunetnat_dep,
        gcrypt_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-communicator-tcp',
    gnunetcommunicatortcp_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunettransportcommunicator_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunetnat_dep,
        gcrypt_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
if quic_dep.found() and get_option('experimental')
    executable(
        'gnunet-communicator-quic',
        gnunetcommunicatorquic_src,
        install_rpath: rpath_option,
        dependencies: [
            libgnunettransportcommunicator_dep,
            libgnunettransportapplication_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunetnat_dep,
            gcrypt_dep,
            quic_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet' / 'libexec',
    )
endif
if http3_enabled
    executable(
        'gnunet-communicator-http3',
        gnunetcommunicatorhttp3_src,
        install_rpath: rpath_option,
        dependencies: [
            libgnunettransportcommunicator_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            gnutls_dep,
            gcrypt_dep,
            libgnunetnat_dep,
            ngtcp2_dep,
            ngtcp2_crypto_dep,
            nghttp3_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet' / 'libexec',
    )
endif

if false
    libgnunettesttransport_cmd_simplesend = library(
        'gnunet_test_transport_plugin_cmd_simple_send',
        ['test_transport_plugin_cmd_simple_send.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )

    libgnunettesttransport_cmd_simplesendbc = library(
        'gnunet_test_transport_plugin_cmd_simple_send_broadcast',
        ['test_transport_plugin_cmd_simple_send_broadcast.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )

    libgnunettesttransport_cmd_simplesenddv = library(
        'gnunet_test_transport_plugin_cmd_simple_send_dv',
        ['test_transport_plugin_cmd_simple_send_dv.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )

    libgnunettesttransport_cmd_simplesendperf = library(
        'gnunet_test_transport_plugin_cmd_simple_send_performance',
        ['test_transport_plugin_cmd_simple_send_performance.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )

    libgnunettesttransport_cmd_udpback = library(
        'gnunet_test_transport_plugin_cmd_udp_backchannel',
        ['test_transport_plugin_cmd_udp_backchannel.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettestingtransport_dep,
            libgnunettransportapplication_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )

    libgnunettesttransport_cmd_natupnp = library(
        'gnunet_test_transport_plugin_cmd_nat_upnp',
        ['test_transport_plugin_cmd_nat_upnp.c'],
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir') / 'gnunet',
    )
endif

configure_file(
    input: 'test_transport_defaults.conf',
    output: 'test_transport_defaults.conf',
    copy: true,
)

foreach p : ['unix', 'tcp', 'udp', 'quic', 'http3']
    configure_file(
        input: 'test_communicator_' + p + '_basic_peer1.conf',
        output: 'test_communicator_' + p + '_basic_peer1.conf',
        copy: true,
    )
    configure_file(
        input: 'test_communicator_' + p + '_basic_peer2.conf',
        output: 'test_communicator_' + p + '_basic_peer2.conf',
        copy: true,
    )
endforeach

foreach p : ['tcp', 'udp']
    configure_file(
        input: 'test_communicator_' + p + '_rekey_peer1.conf',
        output: 'test_communicator_' + p + '_rekey_peer1.conf',
        copy: true,
    )
    configure_file(
        input: 'test_communicator_' + p + '_rekey_peer2.conf',
        output: 'test_communicator_' + p + '_rekey_peer2.conf',
        copy: true,
    )
endforeach

configure_file(
    input: 'test_communicator_udp_backchannel_peer1.conf',
    output: 'test_communicator_udp_backchannel_peer1.conf',
    copy: true,
)
configure_file(
    input: 'test_communicator_udp_backchannel_peer2.conf',
    output: 'test_communicator_udp_backchannel_peer2.conf',
    copy: true,
)

configure_file(
    input: 'test_communicator_tcp_bidirect_peer1.conf',
    output: 'test_communicator_tcp_bidirect_peer1.conf',
    copy: true,
)
configure_file(
    input: 'test_communicator_tcp_bidirect_peer2.conf',
    output: 'test_communicator_tcp_bidirect_peer2.conf',
    copy: true,
)

testcommunicator_basic_unix = executable(
    'test_communicator_basic-unix',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)
testcommunicator_basic_tcp = executable(
    'test_communicator_basic-tcp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)
testcommunicator_basic_udp = executable(
    'test_communicator_basic-udp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)
if quic_dep.found() and get_option('experimental')
    testcommunicator_basic_quic = executable(
        'test_communicator_basic-quic',
        ['test_communicator_basic.c'],
        install_rpath: rpath_option,
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettestingtransport_dep,
            libgnunettransportcore_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: false,
    )
endif
if http3_enabled
    testcommunicator_basic_http3 = executable(
        'test_communicator_basic-http3',
        ['test_communicator_basic.c'],
        install_rpath: rpath_option,
        dependencies: [
            libgnunetutil_dep,
            libgnunettransportapplication_dep,
            libgnunettransportcore_dep,
            libgnunettestingtransport_dep,
            libgnunettesting_dep,
            libgnunetpeerstore_dep,
            libgnunetstatistics_dep,
            libgnunethello_dep,
            libgnunetarm_dep,
            libgnunetutil_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: false,
    )
endif

testcommunicator_rekey_tcp = executable(
    'test_communicator_rekey-tcp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testcommunicator_rekey_udp = executable(
    'test_communicator_rekey-udp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testcommunicator_backchannel_udp = executable(
    'test_communicator_backchannel-udp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testcommunicator_bidirect_tcp = executable(
    'test_communicator_bidirect-tcp',
    ['test_communicator_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettransportapplication_dep,
        libgnunettestingtransport_dep,
        libgnunettransportcore_dep,
        libgnunettesting_dep,
        libgnunetpeerstore_dep,
        libgnunetstatistics_dep,
        libgnunethello_dep,
        libgnunetarm_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)


if false
    testtransport_test_names = [
        'test_transport_start_testcase',
        'test_transport_simple_send_performance',
        'test_transport_nat_icmp_tcp',
        'test_transport_nat_upnp',
        'test_transport_simple_send_string',
        'test_transport_simple_send',
        'test_transport_simple_send_broadcast',
        'test_transport_udp_backchannel',
        'test_transport_simple_send_dv_circle',
        'test_transport_simple_send_dv_inverse',
    ]

    foreach t : testtransport_test_names

        test_filename = t + '.sh'
        test_file = configure_file(
            input: test_filename,
            output: test_filename,
            copy: true,
        )

        if host_machine.system() != 'darwin'
            test(
                t,
                test_file,
                suite: 'transport',
                workdir: meson.current_build_dir(),
                is_parallel: false,
            )
        endif
    endforeach
endif

test(
    'test_communicator_basic-unix',
    testcommunicator_basic_unix,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
test(
    'test_communicator_basic-tcp',
    testcommunicator_basic_tcp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
test(
    'test_communicator_basic-udp',
    testcommunicator_basic_udp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
if quic_dep.found() and get_option('experimental')
    test(
        'test_communicator_basic-quic',
        testcommunicator_basic_quic,
        workdir: meson.current_build_dir(),
        suite: ['transport', 'communicator'],
        is_parallel: false,
    )
endif
if http3_enabled
    test(
        'test_communicator_basic-http3',
        testcommunicator_basic_http3,
        workdir: meson.current_build_dir(),
        suite: ['transport', 'communicator'],
        is_parallel: false,
    )
endif
test(
    'test_communicator_rekey-tcp',
    testcommunicator_rekey_tcp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
test(
    'test_communicator_rekey-udp',
    testcommunicator_rekey_udp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
test(
    'test_communicator_backchannel-udp',
    testcommunicator_backchannel_udp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
test(
    'test_communicator_bidirect-tcp',
    testcommunicator_bidirect_tcp,
    workdir: meson.current_build_dir(),
    suite: ['transport', 'communicator'],
    is_parallel: false,
)
