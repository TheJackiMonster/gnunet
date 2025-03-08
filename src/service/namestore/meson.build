libgnunetnamestore_src = ['namestore_api.c', 'namestore_api_monitor.c']

gnunetservicenamestore_src = ['gnunet-service-namestore.c']

configure_file(
    input: 'namestore.conf.in',
    output: 'namestore.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)


if get_option('monolith')
    foreach p : libgnunetnamestore_src + gnunetservicenamestore_src
        gnunet_src += 'namestore/' + p
    endforeach
endif

libgnunetnamestore = library(
    'gnunetnamestore',
    libgnunetnamestore_src,
    soversion: solibversions['libgnunetnamestore']['soversion'],
    version: solibversions['libgnunetnamestore']['version'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetutil_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetnamestore_dep = declare_dependency(link_with: libgnunetnamestore)
pkg.generate(
    libgnunetnamestore,
    url: 'https://www.gnunet.org',
    description: 'Provides API for storing GNS records to a database',
)

executable(
    'gnunet-service-namestore',
    gnunetservicenamestore_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetnamestore_dep,
        libgnunetutil_dep,
        libgnunetnamecache_dep,
        libgnunetgnsrecord_dep,
        libgnunetidentity_dep,
        libgnunetstatistics_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

configure_file(
    copy: true,
    input: 'test_namestore_api.conf',
    output: 'test_namestore_api.conf',
)

configure_file(
    copy: true,
    input: 'test_namestore_api_sqlite.conf',
    output: 'test_namestore_api_sqlite.conf',
)

configure_file(
    copy: true,
    input: 'test_namestore_api_postgres.conf',
    output: 'test_namestore_api_postgres.conf',
)

if false

    namestoreapitestnames = [
        'test_namestore_api_lookup_nick',
        'test_namestore_api_monitoring',
        'test_namestore_api_monitoring_existing',
        'test_namestore_api_remove',
        'test_namestore_api_remove_not_existing_record',
        'test_namestore_api_store',
        'test_namestore_api_store_update',
        'test_namestore_api_zone_iteration',
        'test_namestore_api_zone_iteration_nick',
        'test_namestore_api_zone_iteration_specific_zone',
        'test_namestore_api_zone_iteration_stop',
        'test_namestore_api_zone_to_name',
        'test_namestore_api_edit_records',
    ]

    foreach tn : namestoreapitestnames
        t = executable(
            tn + '_sqlite',
            [tn + '.c'],
            dependencies: [
                libgnunettesting_dep,
                libgnunetutil_dep,
                libgnunetgnsrecord_dep,
                libgnunetidentity_dep,
                libgnunetnamestore_dep,
            ],
            include_directories: [incdir, configuration_inc],
            install: false,
        )
        test(
            tn + '_sqlite',
            t,
            workdir: meson.current_build_dir(),
            is_parallel: false,
            suite: 'namestore',
        )
        if pq_dep.found()
            t_pq = executable(
                tn + '_postgres',
                [tn + '.c'],
                dependencies: [
                    libgnunettesting_dep,
                    libgnunetutil_dep,
                    libgnunetgnsrecord_dep,
                    libgnunetidentity_dep,
                    libgnunetnamestore_dep,
                ],
                include_directories: [incdir, configuration_inc],
                install: false,
            )
            test(
                tn + '_postgres',
                t_pq,
                workdir: meson.current_build_dir(),
                is_parallel: false,
                suite: 'namestore',
            )
        endif
    endforeach

endif

# FIXME perf tests missing
