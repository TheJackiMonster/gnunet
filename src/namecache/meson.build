libgnunetnamecache_src = ['namecache_api.c']
libgnunetpluginnamecache_sqlite_src = ['plugin_namecache_sqlite.c']

gnunetnamecache_src = ['gnunet-namecache.c']
gnunetservicenamecache_src = ['gnunet-service-namecache.c']

configure_file(input : 'namecache.conf.in',
               output : 'namecache.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetnamecache = library('gnunetnamecache',
          libgnunetnamecache_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetnamecache_dep = declare_dependency(link_with : libgnunetnamecache)
  libgnunetpluginnamecache_sqlite = library('gnunet_plugin_namecache_sqlite',
          libgnunetpluginnamecache_sqlite_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         sqlite_dep,
                         libgnunetsq_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetpluginnamecache_sqlite_dep = declare_dependency(link_with : libgnunetpluginnamecache_sqlite)
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
else
  foreach p : libgnunetnamecache_src + libgnunetpluginnamecache_sqlite_src + gnunetservicenamecache_src
    gnunet_src += 'namecache/' + p
  endforeach
endif
