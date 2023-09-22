libgnunetdatacache_src = ['datacache.c']

libgnunetplugindatacache_sqlite_src = ['plugin_datacache_sqlite.c']

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
endif

libgnunetdatacache = library('gnunetdatacache',
        libgnunetdatacache_src,
        soversion: '0.1.0',
        dependencies: [libgnunetutil_dep, libgnunetstatistics_dep],
        include_directories: [incdir, configuration_inc])
libgnunetdatacache_dep = declare_dependency(link_with : libgnunetdatacache)
pkg.generate(libgnunetdatacache, url: 'https://www.gnunet.org',
             description : 'Provides datacache API for temporary storage to disk')
shared_module('gnunet_plugin_datacache_sqlite',
        libgnunetplugindatacache_sqlite_src,
        dependencies: [libgnunetutil_dep,
                       libgnunetdatacache_dep,
                       sqlite_dep,
                       libgnunetsq_dep],
        include_directories: [incdir, configuration_inc])
