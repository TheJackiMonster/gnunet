coresrc = ['core_api.c',
           'core_api_monitor_peers.c',
           'gnunet-service-core.c',
           'gnunet-service-core_kx.c',
           'gnunet-service-core_sessions.c',
           'gnunet-service-core_typemap.c'
	         ]

library('gnunetcore',
        coresrc,
        dependencies: gnunetutil_dep,
        include_directories: [incdir, configuration_inc])
