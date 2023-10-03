libgnunetutil_src = ['bandwidth.c',
       # $(BENCHMARK)',
       'bio.c',
       'buffer.c',
       'child_management.c',
       'client.c',
       'common_allocation.c',
       'common_endian.c',
       'common_logging.c',
       'compress.c',
       'configuration.c',
       'configuration_helper.c',
       'consttime_memcmp.c',
       'container_bloomfilter.c',
       'container_heap.c',
       'container_multihashmap.c',
       'container_multishortmap.c',
       'container_multiuuidmap.c',
       'container_multipeermap.c',
       'container_multihashmap32.c',
       'crypto_symmetric.c',
       'crypto_crc.c',
       'crypto_cs.c',
       'crypto_ecc.c',
       'crypto_ecc_gnsrecord.c',
       'crypto_ecc_dlog.c',
       'crypto_ecc_setup.c',
       'crypto_edx25519.c',
       'crypto_hash.c',
       'crypto_hash_file.c',
       'crypto_hkdf.c',
       'crypto_kdf.c',
       'crypto_mpi.c',
       'crypto_paillier.c',
       'crypto_pow.c',
       'crypto_random.c',
       'crypto_rsa.c',
       'disk.c',
       'disk.h',
       'dnsparser.c',
       'dnsstub.c',
       'getopt.c',
       'getopt_helpers.c',
       'helper.c',
       'load.c',
       'mst.c',
       'mq.c',
       'nc.c',
       'network.c',
       'op.c',
       'os_installation.c',
       'os_network.c',
       'os_priority.c',
       'peer.c',
       'plugin.c',
       'program.c',
       'regex.c',
       'resolver_api.c',
       'resolver.h',
       'scheduler.c',
       'service.c',
       'signal.c',
       'strings.c',
       'time.c',
       'tun.c',
       'uri.c',
       'speedup.c',
       'speedup.h',
       'proc_compat.c',
	     'gnunet_error_codes.c']

gnunetserviceresolver_src = ['gnunet-service-resolver.c']

configure_file(input : 'util.conf',
               output : 'util.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)
configure_file(input : 'resolver.conf.in',
               output : 'resolver.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : [libgnunetutil_src, gnunetserviceresolver_src]
    gnunet_src += 'util/' + p
  endforeach
  subdir_done()
endif

libgnunetutil = library('gnunetutil',
        libgnunetutil_src,
        soversion: '15',
        version: '15.0.0',
        dependencies: gnunetdeps,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetutil_dep = declare_dependency(link_with : libgnunetutil)
pkg.generate(libgnunetutil, url: 'https://www.gnunet.org',
             description : 'Provides miscellaneous utility functions and API for GNUnet')

shared_module('gnunet_plugin_utiltest',
              ['test_plugin_plug.c'],
              dependencies: [libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir')/'gnunet')

executable ('gnunet-base32',
            ['gnunet-base32.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-config',
            ['gnunet-config.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-resolver',
            ['gnunet-resolver.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-ecc',
            ['gnunet-ecc.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep, gcrypt_dep, m_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-scrypt',
            ['gnunet-scrypt.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-uri',
            ['gnunet-uri.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
if zbar_dep.found()
  executable ('gnunet-qr',
              ['gnunet-qr.c'],
              dependencies: [zbar_dep, libgnunetutil_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('bindir'))
endif
executable ('gnunet-config-diff',
            ['gnunet-config-diff.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

executable ('gnunet-service-resolver',
            gnunetserviceresolver_src,
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
executable ('gnunet-timeout',
            ['gnunet-timeout.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')


executable ('test_common_logging_dummy',
            ['test_common_logging_dummy.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: false)
executable ('gnunet-crypto-tvg',
            ['gnunet-crypto-tvg.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep, json_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

testcommonalloc = executable ('test_common_allocation',
            ['test_common_allocation.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            build_by_default: false,
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_common_allocation', testcommonalloc,
     workdir: meson.current_source_dir(),
     suite: ['util', 'util-common'])
testcommonlog = executable ('test_common_logging',
            ['test_common_logging.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            build_by_default: false,
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_common_logging', testcommonlog,
     workdir: meson.current_source_dir(),
     suite: ['util', 'util-common'])
testcommonendian = executable ('test_common_endian',
            ['test_common_endian.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            build_by_default: false,
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_common_endian', testcommonendian,
     workdir: meson.current_source_dir(),
     suite: ['util', 'util-common'])
testconf = executable ('test_configuration',
            ['test_configuration.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            build_by_default: false,
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_configuration', testconf,
     workdir: meson.current_source_dir(),
     suite: ['util', 'util-configuration'])
testcontainerbloom = executable ('test_container_bloomfilter',
            ['test_container_bloomfilter.c'],
            dependencies: [libgnunetutil_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            build_by_default: false,
            install: false)
test('test_container_bloomfilter', testcontainerbloom,
     workdir: meson.current_source_dir(),
     suite: ['util', 'util-container'])
