libgnunetats_src = ['ats_api_connectivity.c',
                    'ats_api_scheduling.c',
                    'ats_api_scanner.c',
                    'ats_api_performance.c']

gnunetserviceats_src = ['gnunet-service-ats.c',
                        'gnunet-service-ats_addresses.c',
                        'gnunet-service-ats_connectivity.c',
                        'gnunet-service-ats_normalization.c',
                        'gnunet-service-ats_performance.c',
                        'gnunet-service-ats_plugins.c',
                        'gnunet-service-ats_preferences.c',
                        'gnunet-service-ats_scheduling.c',
                        'gnunet-service-ats_reservations.c']

configure_file(input : 'ats.conf.in',
               output : 'ats.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetats_src + gnunetserviceats_src
    gnunet_src += 'ats/' + p
  endforeach
  subdir_done()
endif

libgnunetats = library('gnunetats',
        libgnunetats_src,
        version: '4.0.0',
        soversion: '4',
        dependencies: [libgnunetutil_dep, libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetats, url : 'https://www.gnunet.org',
             description : 'Provides API for allocating bandwidth, expressing preferences for certain peers and accessing allocation information')
libgnunetats_dep = declare_dependency(link_with : libgnunetats)

shared_module('gnunet_plugin_ats_proportional',
        ['plugin_ats_proportional.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetats_dep,
                       libgnunetstatistics_dep,
                       libgnunetnt_dep,
                       libgnunetstatistics_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

executable ('gnunet-service-ats',
            gnunetserviceats_src,
            dependencies: [libgnunetats_dep, libgnunetutil_dep,
                           libgnunetnt_dep, libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
