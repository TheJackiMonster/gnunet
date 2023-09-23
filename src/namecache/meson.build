libgnunetnamecache_src = ['namecache_api.c']

gnunetnamecache_src = ['gnunet-namecache.c']
gnunetservicenamecache_src = ['gnunet-service-namecache.c']

configure_file(input : 'namecache.conf.in',
               output : 'namecache.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetnamecache_src + libgnunetpluginnamecache_sqlite_src + gnunetservicenamecache_src
    gnunet_src += 'namecache/' + p
  endforeach
  subdir_done()
endif

libgnunetnamecache = library('gnunetnamecache',
        libgnunetnamecache_src,
        soversion: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep],
        include_directories: [incdir, configuration_inc])
libgnunetnamecache_dep = declare_dependency(link_with : libgnunetnamecache)
pkg.generate(libgnunetnamecache, url: 'https://www.gnunet.org',
             description : 'Provides API for storing GNS records to a cache')

shared_module('gnunet_plugin_namecache_sqlite',
        ['plugin_namecache_sqlite.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       sqlite_dep,
                       libgnunetsq_dep],
        include_directories: [incdir, configuration_inc])

if pq_dep.found()
  shared_module('gnunet_plugin_namecache_postgres',
          ['plugin_namecache_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         pq_dep,
                         libgnunetpq_dep],
          include_directories: [incdir, configuration_inc])
endif

executable ('gnunet-namecache',
            gnunetnamecache_src,
            dependencies: [libgnunetnamecache_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetidentity_dep],
            include_directories: [incdir, configuration_inc])
executable ('gnunet-service-namecache',
            gnunetservicenamecache_src,
            dependencies: [libgnunetnamecache_dep,
                           libgnunetutil_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc])
