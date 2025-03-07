executable(
    'gnunet-nse',
    ['gnunet-nse.c'],
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [libgnunetnse_dep, m_dep, extractor_dep, libgnunetutil_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

