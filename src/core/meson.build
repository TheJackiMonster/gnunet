libgnunetcore_src = ['core_api.c',
                    'core_api_monitor_peers.c']

gnunetservicecore_src = ['gnunet-service-core.c',
                        'gnunet-service-core_kx.c',
                        'gnunet-service-core_sessions.c',
                        'gnunet-service-core_typemap.c']

configure_file(input : 'core.conf.in',
               output : 'core.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetcore_src + gnunetservicecore_src
    gnunet_src += 'core/' + p
  endforeach
endif

libgnunetcore = library('gnunetcore',
          libgnunetcore_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc],
          install: true,
          soversion: '0.1.0',
          install_dir: get_option('libdir'))
libgnunetcore_dep = declare_dependency(link_with : libgnunetcore)
pkg.generate(libgnunetcore, url: 'https://www.gnunet.org',
             description : 'Provides API for (encrypted) P2P communication')

executable ('gnunet-service-core',
            gnunetservicecore_src,
            dependencies: [libgnunetcore_dep, libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunettransport_dep,
                           zlib_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
