libgnunetdatacache_src = ['datacache.c']

configure_file(
    input: 'datacache.conf',
    output: 'datacache.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

if get_option('monolith')
    foreach p : libgnunetdatacache_src
        gnunet_src += 'datacache/' + p
    endforeach
endif

libgnunetdatacache = library(
    'gnunetdatacache',
    libgnunetdatacache_src,
    soversion: solibversions['libgnunetdatacache']['soversion'],
    version: solibversions['libgnunetdatacache']['version'],
    install_rpath: rpath_option,
    dependencies: [libgnunetutil_dep, libgnunetstatistics_dep],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
libgnunetdatacache_dep = declare_dependency(link_with: libgnunetdatacache)
pkg.generate(
    libgnunetdatacache,
    url: 'https://www.gnunet.org',
    description: 'Provides datacache API for temporary storage to disk',
)

testdc_sqlite = executable(
    'test_datacache_sqlite',
    ['test_datacache.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testdc_quota_sqlite = executable(
    'test_datacache_quota_sqlite',
    ['test_datacache_quota.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testdc_heap = executable(
    'test_datacache_heap',
    ['test_datacache.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testdc_quota_heap = executable(
    'test_datacache_quota_heap',
    ['test_datacache_quota.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)


testdc_pq = executable(
    'test_datacache_postgres',
    ['test_datacache.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

testdc_quota_pq = executable(
    'test_datacache_quota_postgres',
    ['test_datacache_quota.c'],
    dependencies: [
        libgnunetdatacache_dep,
        libgnunetutil_dep,
        libgnunettesting_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: false,
)

configure_file(
    input: 'test_datacache_data_sqlite.conf',
    output: 'test_datacache_data_sqlite.conf',
    copy: true,
)
configure_file(
    input: 'test_datacache_data_heap.conf',
    output: 'test_datacache_data_heap.conf',
    copy: true,
)
configure_file(
    input: 'test_datacache_data_postgres.conf',
    output: 'test_datacache_data_postgres.conf',
    copy: true,
)

test(
    'test_datacache_sqlite',
    testdc_sqlite,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
test(
    'test_datacache_quota_sqlite',
    testdc_quota_sqlite,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
test(
    'test_datacache_heap',
    testdc_heap,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
test(
    'test_datacache_quota_heap',
    testdc_quota_heap,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
test(
    'test_datacache_postgres',
    testdc_pq,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
test(
    'test_datacache_quota_postgres',
    testdc_quota_pq,
    suite: 'datacache',
    workdir: meson.current_build_dir(),
    is_parallel: false,
)
