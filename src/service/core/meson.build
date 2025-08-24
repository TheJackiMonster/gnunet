libgnunetcore_src = ['core_api.c', 'core_api_monitor_peers.c']

gnunetservicecore_src = [
    'gnunet-service-core.c',
    'gnunet-service-core_kx.c',
    'gnunet-service-core_sessions.c',
]

configure_file(
    input: 'core.conf.in',
    output: 'core.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetcore_src + gnunetservicecore_src
        gnunet_src += 'core/' + p
    endforeach
endif

libgnunetcore = library(
    'gnunetcore',
    libgnunetcore_src,
    soversion: solibversions['libgnunetcore']['soversion'],
    version: solibversions['libgnunetcore']['version'],
    install_rpath: rpath_option,
    dependencies: libgnunetutil_dep,
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetcore_dep = declare_dependency(link_with: libgnunetcore)
pkg.generate(
    libgnunetcore,
    url: 'https://www.gnunet.org',
    description: 'Provides API for (encrypted) P2P communication',
)

libgnunettestingcore = library(
    'gnunettestingcore',
    [
        'testing_core_cmd_connect.c',
        'testing_core_cmd_recv.c',
        'testing_core_cmd_send.c',
        'testing_core_traits.c',
    ],
    soversion: solibversions['libgnunettestingcore']['soversion'],
    version: solibversions['libgnunettestingcore']['version'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetcore_dep,
        libgnunetutil_dep,
        libgnunettestbed_dep,
        libgnunettestingtestbed_dep,
        libgnunettestingarm_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunettestingcore_dep = declare_dependency(link_with: libgnunettestingcore)

libgnunetcoreunderlaydummy = library(
    'gnunetcoreunderlaydummy',
    ['gnunet_core_underlay_dummy.c'],
    soversion: '0.0.0',
    version: '0.0.0',
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunettesting_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetcoreunderlaydummy_dep = declare_dependency(
    link_with: libgnunetcoreunderlaydummy,
)

shared_module(
    'gnunet_plugin_testing_core_underlay_dummy',
    ['test_core_plugin_underlay_dummy.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunettesting_dep,
        libgnunetcoreunderlaydummy_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

shared_module(
    'gnunet_plugin_testing_core_basic',
    ['test_core_plugin_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetcore_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
        libgnunettestingcore_dep,
        libgnunettestbed_dep,
        libgnunettestingtestbed_dep,
        libgnunettestingarm_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

executable(
    'gnunet-service-core',
    gnunetservicecore_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunethello_dep,
        libgnunetcore_dep,
        libgnunetpils_dep,
        libgnunetstatistics_dep,
        libgnunettransportapplication_dep,
        libgnunettransportcore_dep,
        zlib_dep,
        sodium_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

configure_file(
    input: 'test_core_defaults.conf',
    output: 'test_core_defaults.conf',
    copy: true,
)

configure_file(
    input: 'test_core_api_send_to_self.conf',
    output: 'test_core_api_send_to_self.conf',
    copy: true,
)

configure_file(
    input: 'test_core_api_peer1.conf',
    output: 'test_core_api_peer1.conf',
    copy: true,
)

configure_file(
    input: 'test_core_api_peer2.conf',
    output: 'test_core_api_peer2.conf',
    copy: true,
)

configure_file(
    input: 'test_core_api_data.conf',
    output: 'test_core_api_data.conf',
    copy: true,
)

configure_file(
    input: 'test_core_basic_peer.conf',
    output: 'test_core_basic_peer.conf',
    copy: true,
)

configure_file(
    input: 'test_core_basic_topo.conf',
    output: 'test_core_basic_topo.conf',
    copy: true,
)

testcore_underlay_dummy = executable(
    'test_core_underlay_dummy',
    ['test_core_underlay_dummy.c'],
    dependencies: [libgnunetcoreunderlaydummy_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)

test(
    'test_core_underlay_dummy',
    testcore_underlay_dummy,
    suite: 'core',
    workdir: meson.current_build_dir(),
)

# FIXME: Name of binary. Install directory?
executable(
    'test-core-underlay-dummy-testing-launcher',
    ['test_core_underlay_dummy_testing_launcher.c'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunettesting_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

if false

    testcore_api_send_self = executable(
        'test_core_api_send_to_self',
        ['test_core_api_send_to_self.c'],
        dependencies: [
            libgnunetcore_dep,
            libgnunetutil_dep,
            libgnunettesting_dep,
        ],
        include_directories: [incdir, configuration_inc],
        install: false,
    )

    test(
        'test_core_api_send_to_self',
        testcore_api_send_self,
        suite: 'core',
        workdir: meson.current_build_dir(),
    )
endif

testcore_api_start = executable(
    'test_core_api_start_only',
    ['test_core_api_start_only.c'],
    dependencies: [libgnunetcore_dep, libgnunetutil_dep, libgnunettesting_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)

test(
    'test_core_api_start_only',
    testcore_api_start,
    suite: 'core',
    workdir: meson.current_build_dir(),
)

# FIXME test_core_basic
#      this currently works on my (ch3) machine, but is not expected to work on
#      others. It is expecting the netjail testing scripts in a location
#      specific to my machine, because currently they're not available in the
#      build dir
testcore_basic = find_program(
    'test_core_basic.sh',
    # TODO specify current working/build dir if possible
)

test(
    'test_core_basic',
    testcore_basic,
    suite: 'core',
    workdir: meson.current_build_dir(),
    #depends: [
    #    libgnunettesting_dep
    #],
)

# FIXME: add shell script tests: test_core_start_testcase.sh, test_core_underlay_dummy.sh
