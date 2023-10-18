libgnunetsecretsharing_src = ['secretsharing_api.c', 'secretsharing_common.c']

gnunetservicesecretsharing_src = ['gnunet-service-secretsharing.c', 'secretsharing_common.c']

configure_file(input : 'secretsharing.conf.in',
               output : 'secretsharing.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

# FIXME needs new seti/setu
if get_option('monolith')
  #foreach p : libgnunetsecretsharing_src + gnunetservicesecretsharing_src
  #  gnunet_src += 'secretsharing/' + p
  #endforeach
  subdir_done()
endif

libgnunetsecretsharing = library('gnunetsecretsharing',
        libgnunetsecretsharing_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetstatistics_dep,
                       gcrypt_dep,
                       libgnunetdatacache_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetsecretsharing_dep = declare_dependency(link_with : libgnunetsecretsharing)
pkg.generate(libgnunetsecretsharing, url: 'https://www.gnunet.org',
             description : 'Provides API for the secretsharing service')

executable ('gnunet-service-secretsharing',
            gnunetservicesecretsharing_src,
            dependencies: [libgnunetsecretsharing_dep,
                           libgnunetutil_dep,
                           gcrypt_dep,
                           m_dep,
                           libgnunetconsensus_dep,
                           libgnunetstatistics_dep,
                           libgnunetdatacache_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

