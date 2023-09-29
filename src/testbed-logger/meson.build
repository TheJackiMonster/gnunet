libgnunettestbedlogger_src = ['testbed_logger_api.c']

configure_file(input : 'testbed-logger.conf',
               output : 'testbed-logger.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  subdir_done()
endif

libgnunettestbedlogger = library('gnunettestbed',
        libgnunettestbedlogger_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettestbedlogger_dep = declare_dependency(link_with : libgnunettestbedlogger)


executable ('gnunet-service-testbed-logger',
            ['gnunet-service-testbed-logger.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
