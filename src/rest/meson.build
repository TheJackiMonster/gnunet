libgnunetrest_src = ['rest.c']

gnunetservicerest_src = ['gnunet-rest-server.c']

configure_file(input : 'rest.conf',
               output : 'rest.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetrest_src + gnunetservicerest_src
    gnunet_src += 'rest/' + p
  endforeach
  subdir_done()
endif


libgnunetrest = library('gnunetrest',
        libgnunetrest_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, mhd_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetrest, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the REST service')
libgnunetrest_dep = declare_dependency(link_with : libgnunetrest)

shared_module('gnunet_plugin_rest_config',
              ['plugin_rest_config.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')
shared_module('gnunet_plugin_rest_copying',
              ['plugin_rest_copying.c'],
              dependencies: [libgnunetrest_dep,
                             libgnunetutil_dep,
                             json_dep,
                             mhd_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir') / 'gnunet' / 'libexec')


executable ('gnunet-rest-server',
            gnunetservicerest_src,
            dependencies: [libgnunetrest_dep, libgnunetutil_dep, mhd_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

