libgnunetdatacache_src = ['datacache.c']

configure_file(input : 'datacache.conf',
               output : 'datacache.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)
install_data ('datacache-0001.sql',
              'datacache-drop.sql',
               install_dir: get_option('datadir')/'gnunet'/'sql')

if get_option('monolith')
  foreach p : libgnunetdatacache_src
    gnunet_src += 'datacache/' + p
  endforeach
  subdir_done()
endif

libgnunetdatacache = library('gnunetdatacache',
        libgnunetdatacache_src,
        soversion: '0',
        version: '0.0.1',
        dependencies: [libgnunetutil_dep, libgnunetstatistics_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetdatacache_dep = declare_dependency(link_with : libgnunetdatacache)
pkg.generate(libgnunetdatacache, url: 'https://www.gnunet.org',
             description : 'Provides datacache API for temporary storage to disk')

shared_module('gnunet_plugin_datacache_sqlite',
        ['plugin_datacache_sqlite.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetdatacache_dep,
                       sqlite_dep,
                       libgnunetsq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')
shared_module('gnunet_plugin_datacache_heap',
        ['plugin_datacache_heap.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetdatacache_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')


if pq_dep.found()
  shared_module('gnunet_plugin_datacache_postgres',
          ['plugin_datacache_postgres.c'],
          dependencies: [libgnunetutil_dep,
                         libgnunetdatacache_dep,
                         pq_dep,
                         libgnunetpq_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')
endif
