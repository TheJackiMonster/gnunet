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
  dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir'))
pkg.generate(libgnunetarm, url: 'https://www.gnunet.org',
  description : 'Provides API for accessing the Automated Restart Manager service')
libgnunetarm_dep = declare_dependency(link_with : libgnunetarm)

executable ('gnunet-service-arm',
  gnunetservicearm_src,
  dependencies: [gcrypt_dep, sodium_dep, libgnunetarm_dep, libgnunetutil_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir') / 'gnunet' / 'libexec')