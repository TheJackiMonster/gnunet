libgnunetarm_src = ['arm_api.c',
  'arm_monitor_api.c']

gnunetservicearm_src = ['gnunet-service-arm.c']

testarmapi_src = ['test_arm_api.c']
testexpbo_src = ['test_exponential_backoff.c']
testgnunetservice_src = ['test_gnunet_service_arm.c']

configure_file(input : 'arm.conf.in',
  output : 'arm.conf',
  configuration : cdata,
  install: true,
  install_dir: pkgcfgdir)

libgnunetarm = library('gnunetarm',
  libgnunetarm_src,
  soversion: solibversions['libgnunetarm']['soversion'],
  version: solibversions['libgnunetarm']['version'],
  install_rpath: get_option('prefix') / get_option('libdir'),
  dependencies: libgnunetutil_dep,
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir'))
pkg.generate(libgnunetarm, url: 'https://www.gnunet.org',
  description : 'Provides API for accessing the Automated Restart Manager service')
libgnunetarm_dep = declare_dependency(link_with : libgnunetarm)

executable ('gnunet-service-arm',
  gnunetservicearm_src,
  dependencies: [libgnunetarm_dep, libgnunetutil_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir') / 'gnunet' / 'libexec')

mockservice = executable ('mockup-service',
  ['mockup-service.c'],
  dependencies: [libgnunetarm_dep, libgnunetutil_dep],
  include_directories: [incdir, configuration_inc],
  install: false)

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

# FIXME: We need to convert the convoluted awk script from Makefile.am here
#configure_file(copy: true,
#               input: 'test_gnunet_arm.py.in',
#               output: 'test_gnunet_arm.py')

test('test_arm_api', testarmapi, workdir: meson.current_build_dir(),
  is_parallel: false,
  suite: 'arm')
test('test_exponential_backoff', testexpbo, workdir: meson.current_build_dir(),
  depends: mockservice,
  is_parallel: false,
  timeout: 60, suite: 'arm')
test('test_gnunet_service_arm', testgnunetservice, workdir: meson.current_build_dir(),
  is_parallel: false,
  suite: 'arm')
