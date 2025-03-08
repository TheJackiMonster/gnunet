libgnunetgns_src = ['gns_api.c', 'gns_tld_api.c']

gnunetservicegns_src = [
    'gnunet-service-gns.c',
    'gnunet-service-gns_resolver.c',
    'gnunet-service-gns_interceptor.c',
]

gnunetgnsproxy_src = ['gnunet-gns-proxy.c']

configure_file(
    input: 'gns.conf.in',
    output: 'gns.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)
configure_file(
    input: 'tlds.conf',
    output: 'tlds.conf',
    configuration: cdata,
    install: true,
    install_dir: pkgcfgdir,
)

if get_option('monolith')
    foreach p : libgnunetgns_src + gnunetservicegns_src
        gnunet_src += 'gns/' + p
    endforeach
endif

libgnunetgns = library(
    'gnunetgns',
    libgnunetgns_src,
    soversion: solibversions['libgnunetgns']['soversion'],
    version: solibversions['libgnunetgns']['version'],
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
libgnunetgns_dep = declare_dependency(link_with: libgnunetgns)
pkg.generate(
    libgnunetgns,
    url: 'https://www.gnunet.org',
    description: 'Provides API to access the GNU Name System',
)

executable(
    'gnunet-gns-proxy',
    gnunetgnsproxy_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetgns_dep,
        libgnunetutil_dep,
        mhd_dep,
        idn_dep,
        curl_dep,
        gnutls_dep,
        libgnunetidentity_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

executable(
    'gnunet-service-gns',
    gnunetservicegns_src,
    install_rpath: rpath_option,
    dependencies: [
        libgnunetgns_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetdht_dep,
        libgnunetdns_dep,
        idn_dep,
        libgnunetidentity_dep,
        libgnunetnamecache_dep,
        libgnunetrevocation_dep,
        libgnunetgnsrecord_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)

executable(
    'gnunet-bcd',
    ['gnunet-bcd.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetgns_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetcore_dep,
        libgnunetdht_dep,
        libgnunetdns_dep,
        mhd_dep,
        idn_dep,
        libgnunetidentity_dep,
        libgnunetnamecache_dep,
        libgnunetrevocation_dep,
        libgnunetgnsrecord_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)
executable(
    'gnunet-dns2gns',
    ['gnunet-dns2gns.c'],
    install_rpath: rpath_option,
    dependencies: [
        libgnunetgns_dep,
        libgnunetutil_dep,
        libgnunetstatistics_dep,
        libgnunetvpn_dep,
        libgnunetcore_dep,
        libgnunetdht_dep,
        libgnunetdns_dep,
        idn_dep,
        libgnunetidentity_dep,
        libgnunetnamecache_dep,
        libgnunetrevocation_dep,
        libgnunetgnsrecord_dep,
        libgnunetcadet_dep,
        libgnunetblock_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('libdir') / 'gnunet' / 'libexec',
)


if have_nss
    subdir('nss')
endif
