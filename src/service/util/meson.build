gnunetserviceresolver_src = ['gnunet-service-resolver.c']

configure_file(
    input: 'resolver.conf.in',
    output: 'resolver.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : gnunetserviceresolver_src
        gnunet_src += 'util/' + p
    endforeach
endif

executable(
    'gnunet-service-resolver',
    gnunetserviceresolver_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

testresolverapi = executable(
    'test_resolver_api',
    ['test_resolver_api.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)
configure_file(
    copy: true,
    input: 'test_resolver_api_data.conf',
    output: 'test_resolver_api_data.conf',
)

test(
    'test_resolver_api',
    testresolverapi,
    workdir: meson.current_build_dir(),
    suite: 'resolver',
)

