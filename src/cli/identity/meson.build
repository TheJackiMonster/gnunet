executable ('gnunet-identity',
            ['gnunet-identity.c'],
            dependencies: [libgnunetidentity_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

test_messages = configure_file(input : 'test_identity_messages.sh',
               output : 'test_identity_messages.sh',
               copy: true)

test('test_identity_messages', test_messages,
     workdir: meson.current_build_dir(),
     suite: ['identity'])
