configure_file(
    input: 'gnunet-gns-proxy-setup-ca.in',
    output: 'gnunet-gns-proxy-setup-ca',
    configuration: cdata,
    install: true,
    install_mode: 'rwxr-xr-x',
    install_dir: get_option('bindir'),
)

install_data(
    'gnunet-gns-proxy-ca.template',
    install_dir: get_option('datadir') / 'gnunet',
)
install_data('openssl.cnf', install_dir: get_option('datadir') / 'gnunet')

executable(
    'gnunet-gns',
    'gnunet-gns.c',
    install_rpath: get_option('prefix') / get_option('libdir'),
    dependencies: [
        libgnunetgns_dep,
        libgnunetgnsrecord_dep,
        idn_dep,
        libgnunetutil_dep,
    ],
    include_directories: [incdir, configuration_inc],
    install: true,
    install_dir: get_option('bindir'),
)

testgns = [
    'test_dns2gns',
    'test_gns_at_lookup',
    'test_gns_caa_lookup',
    'test_gns_config_lookup',
    'test_gns_delegated_lookup',
    'test_gns_dht_lookup',
    'test_gns_gns2dns_cname_lookup',
    'test_gns_gns2dns_lookup',
    'test_gns_gns2dns_zkey_lookup',
    'test_gns_ipv6_lookup',
    'test_gns_lookup',
    'test_gns_mx_lookup',
    'test_gns_quickupdate',
    'test_gns_redirect_lookup',
    'test_gns_rel_expiration',
    'test_gns_revocation',
    'test_gns_soa_lookup',
    'test_gns_txt_lookup',
    'test_gns_zkey_lookup',
    'test_gns_sbox_simple',
    'test_gns_sbox',
    'test_gns_box_sbox',
]

testconfigs = [
    'test_dns2gns.conf',
    'test_gns_defaults.conf',
    'test_gns_lookup.conf',
    'test_gns_lookup_peer1.conf',
    'test_gns_lookup_peer2.conf',
    'test_gns_simple_lookup.conf',
]

foreach f : testconfigs
    configure_file(input: f, output: f, copy: true)
endforeach

foreach t : testgns

    test_filename = t + '.sh'
    test_file = configure_file(
        input: test_filename,
        output: test_filename,
        copy: true,
    )

    test(
        t,
        test_file,
        suite: 'gns',
        workdir: meson.current_build_dir(),
        is_parallel: false,
    )
endforeach
