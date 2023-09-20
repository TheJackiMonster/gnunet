libgnunetdatacache_src = ['datacache.c']

libgnunetplugindatacache_sqlite_src = ['plugin_datacache_sqlite.c']

if gnunet_monolith == false
  libgnunetdatacache = library('gnunetdatacache',
          libgnunetdatacache_src,
          dependencies: [libgnunetutil_dep, libgnunetstatistics_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetdatacache_dep = declare_dependency(link_with : libgnunetdatacache)
  libgnunetplugindatacache_sqlite = library('gnunet_plugin_datacache_sqlite',
          libgnunetplugindatacache_sqlite_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetdatacache_dep,
                         sqlite_dep,
                         libgnunetsq_dep],
          include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetdatacache_src
    gnunet_src += 'datacache/' + p
  endforeach
endif
