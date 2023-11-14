libgnunetnamecache_src = ['namecache_api.c']

gnunetnamecache_src = ['gnunet-namecache.c']
gnunetservicenamecache_src = ['gnunet-service-namecache.c']

configure_file(input : 'namecache.conf.in',
               output : 'namecache.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetnamecache_src + gnunetservicenamecache_src
    gnunet_src += 'namecache/' + p
  endforeach
endif

libgnunetnamecache = library('gnunetnamecache',
        libgnunetnamecache_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetnamecache_dep = declare_dependency(link_with : libgnunetnamecache)
pkg.generate(libgnunetnamecache, url: 'https://www.gnunet.org',
             description : 'Provides API for storing GNS records to a cache')

executable ('gnunet-service-namecache',
            gnunetservicenamecache_src,
            dependencies: [libgnunetnamecache_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

