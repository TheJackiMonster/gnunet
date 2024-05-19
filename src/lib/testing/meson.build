libgnunettesting_src = [
                        'testing_api_barrier.c',
                        'testing_api_cmd_barrier_create.c',
                        'testing_api_cmd_barrier_reached.c',
                        'testing_api_cmd_batch.c',
                        'testing_api_cmd_exec.c',
                        'testing_api_cmd_finish.c',
                        'testing_api_cmd_netjail_start.c',
                        'testing_api_cmd_netjail_start_cmds_helper.c',
                        'testing_api_cmds.c',
                        'testing_api_main.c',
                        'testing_api_loop.c',
                        'testing_api_traits.c'
                        ]

libgnunettesting = library('gnunettesting',
        libgnunettesting_src,
        soversion: '1',
        version: '1.1.0',
        dependencies: [libgnunetutil_dep,
                       m_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettesting_dep = declare_dependency(link_with : libgnunettesting)
pkg.generate(libgnunettesting, url: 'https://www.gnunet.org',
             description : 'Provides API for gnunet testing')

executable ('gnunet-cmds-helper',
            ['gnunet-cmds-helper.c'],
            dependencies: [libgnunettesting_dep,
                           libgnunetutil_dep,
                           ],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
