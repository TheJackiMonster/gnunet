libgnunetrps_src = ['gnunet-service-rps_sampler_elem.c',
                    'rps-test_util.c',
                    'rps-sampler_common.c',
                    'rps-sampler_client.c',
                    'rps_api.c']
gnunetservicerps_src = ['gnunet-service-rps.c',
  'gnunet-service-rps_sampler_elem.c',
  'rps-sampler_common.c',
  'gnunet-service-rps_sampler.c',
  'gnunet-service-rps_custommap.c',
  'gnunet-service-rps_view.c']

configure_file(input : 'rps.conf.in',
               output : 'rps.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetrps_src + gnunetservicerps_src
    gnunet_src += 'rps/' + p
  endforeach
endif

libgnunetrps = library('gnunetrps',
  libgnunetrps_src,
  soversion: solibversions['libgnunetrps']['soversion'],
  version: solibversions['libgnunetrps']['version'],
  install_rpath: get_option('prefix') / get_option('libdir'),
  dependencies: [libgnunetutil_dep,
                 libgnunetnse_dep,
                 m_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir'))
libgnunetrps_dep = declare_dependency(link_with : libgnunetrps)
pkg.generate(libgnunetrps, url: 'https://www.gnunet.org',
             description : 'Peer Sampling Service')

executable ('gnunet-service-rps',
            gnunetservicerps_src,
            dependencies: [libgnunetrps_dep,
                           libgnunetutil_dep,
                           libgnunetcore_dep,
                           libgnunetnse_dep,
                           m_dep,
                           libgnunetpeerstore_dep,
                           libgnunetstatistics_dep,
                           libgnunetcadet_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-rps',
            'gnunet-rps.c',
            dependencies: [libgnunetrps_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

