libgnunetarm_src = ['arm_api.c',
                    'arm_monitor_api.c']

gnunetservicearm_src = ['gnunet-service-arm.c']

gnunetarm_src = ['gnunet-arm.c']

testarmapi_src = ['test_arm_api.c']
testexpbo_src = ['test_exponential_backoff.c']
testgnunetservice_src = ['test_gnunet_service_arm.c']

configure_file(input : 'arm.conf.in',
               output : 'arm.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith') == false
  libgnunetarm = library('gnunetarm',
          libgnunetarm_src,
          dependencies: libgnunetutil_dep,
          soversion: '2.0.0',
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir'))
  libgnunetarm_dep = declare_dependency(link_with : libgnunetarm)
  executable ('gnunet-arm',
              gnunetarm_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('bindir'))
  executable ('gnunet-service-arm',
              gnunetservicearm_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
  testarmapi = executable ('test_arm_api',
              testarmapi_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: false)
  testexpbo = executable ('test_exponential_backoff',
              testexpbo_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: false)
  testgnunetservice = executable ('test_gnunet_service',
              testgnunetservice_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc],
              install: false)
  configure_file(copy: true,
                 input: 'test_arm_api_data.conf',
                 output: 'test_arm_api_data.conf')
  test('test_arm_api', testarmapi)
  test('test_exponential_backoff', testexpbo)
  test('test_gnunet_service', testgnunetservice)
else
  foreach p : libgnunetarm_src + gnunetservicearm_src
    gnunet_src += 'arm/' + p
  endforeach
endif
