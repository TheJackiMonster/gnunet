gnunetservicetemplate_src = ['gnunet-service-template.c']

configure_file(
    input: 'template.conf',
    output: 'template.conf',
    configuration: cdata,
    install: false,
)

executable(
    'gnunet-service-template',
    gnunetservicetemplate_src,
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)
testtemplateapi = executable(
    'test_template_api',
    ['test_template_api.c'],
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)
test(
    'test_template_api',
    testtemplateapi,
    workdir: meson.current_source_dir(),
    suite: ['template', 'contrib'],
)
