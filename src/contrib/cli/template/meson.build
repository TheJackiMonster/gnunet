executable(
    'gnunet-template',
    ['gnunet-template.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: false,
)
