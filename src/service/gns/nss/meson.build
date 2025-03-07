# FIXME:
#
# EXTRA_DIST = map-file
# AM_LDFLAGS=-avoid-version -module -export-dynamic
#
shared_library(
    'nss_gns',
    ['nss_gns_query.c', 'nss_gns.c'],
    soversion: '2',
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    #link_args: ['-fno-version', '-module', '-export-dynamic', '-shrext', '.so.2', '-W', 'l'],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
shared_library(
    'nss_gns4',
    ['nss_gns_query.c', 'nss_gns.c'],
    soversion: '2',
    c_args: ['-DNSS_IPV4_ONLY=1'],
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    #link_args: ['-fno-version', '-module', '-export-dynamic', '-shrext', '.so.2', '-W', 'l'],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
shared_library(
    'nss_gns6',
    ['nss_gns_query.c', 'nss_gns.c'],
    c_args: ['-DNSS_IPV6_ONLY=1'],
    soversion: '2',
    dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep],
    #link_args: ['-fno-version', '-module', '-export-dynamic', '-shrext', '.so.2', '-W', 'l'],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir'),
)
