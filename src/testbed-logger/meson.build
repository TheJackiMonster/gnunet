libgnunettestbedlogger_src = ['testbed_logger_api.c']

tdata = configuration_data()
tdata.merge_from(cdata)
tdata.set_quoted('prefix', get_option('prefix'))

configure_file(input : 'testbed-logger.conf.in',
               output : 'testbed-logger.conf',
               configuration : tdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  subdir_done()
endif

libgnunettestbedlogger = library('gnunettestbedlogger',
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
