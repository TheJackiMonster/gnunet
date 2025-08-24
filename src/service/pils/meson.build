libgnunetpils_src = ['pils_api.c', 'pils.h']

gnunetservicepils_src = ['gnunet-service-pils.c']

configure_file(
    input: 'pils.conf.in',
    output: 'pils.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetpils_src + gnunetservicepils_src
        gnunet_src += 'pils/' + p
    endforeach
endif

libgnunetpils = library(
    'gnunetpils',
    libgnunetpils_src,
    soversion: solibversions['libgnunetpils']['soversion'],
    version: solibversions['libgnunetpils']['version'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunethello_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetpils_dep = declare_dependency(link_with: libgnunetpils)
pkg.generate(
    libgnunetpils,
    url: 'https://www.gnunet.org',
    description: 'Provides API for the PILS service',
)

shared_module(
    'gnunet_plugin_testing_pils_basic',
    ['test_pils_plugin_basic.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunethello_dep,
        libgnunetpils_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
        libgnunettestingarm_dep,
        libgnunettestbed_dep,
        libgnunettestingtestbed_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

executable(
    'gnunet-pils-tvg',
    ['gnunet-pils-tvg.c'],
    dependencies: [libgnunetutil_dep, libgnunethello_dep, libgnunetpils_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)


executable(
    'gnunet-service-pils',
    gnunetservicepils_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunethello_dep,
        libgnunetpils_dep,
        libgnunetstatistics_dep,
        gcrypt_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

configure_file(
    input: 'test_pils_api.conf',
    output: 'test_pils_api.conf',
    copy: true,
)

testpils_api_hello = executable(
    'test_pils_api_hello',
    ['test_pils_api_hello.c'],
    dependencies: [libgnunetpils_dep, libgnunetutil_dep, libgnunethello_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)

test(
    'test_pils_api_hello',
    testpils_api_hello,
    suite: 'pils',
    workdir: meson.current_build_dir(),
)

# FIXME: add shell script tests: test_pils_basic.sh
