executable(
    'gnunet-cadet',
    ['gnunet-cadet.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetcadet_dep,
        extractor_dep,
        libgnunetutil_dep,
        libgnunetcore_dep,
        libgnunetdht_dep,
        m_dep,
        libgnunetstatistics_dep,
        libgnunetpeerstore_dep,
        libgnunettransportapplication_dep,
        libgnunethello_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

