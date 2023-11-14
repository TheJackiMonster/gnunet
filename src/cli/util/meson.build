executable ('gnunet-base32',
            ['gnunet-base32.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-config',
            ['gnunet-config.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-resolver',
            ['gnunet-resolver.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-ecc',
            ['gnunet-ecc.c'],
            dependencies: [libgnunetutil_dep, gcrypt_dep, m_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-scrypt',
            ['gnunet-scrypt.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-uri',
            ['gnunet-uri.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
if zbar_dep.found()
  executable ('gnunet-qr',
              ['gnunet-qr.c'],
              dependencies: [zbar_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('bindir'))
endif
executable ('gnunet-config-diff',
            ['gnunet-config-diff.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

executable ('gnunet-timeout',
            ['gnunet-timeout.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
executable ('gnunet-crypto-tvg',
            ['gnunet-crypto-tvg.c'],
            dependencies: [libgnunetutil_dep, json_dep],
            include_directories: [incdir, configuration_inc],
            install: false)

