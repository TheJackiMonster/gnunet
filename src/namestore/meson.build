libgnunetnamestore_src = ['namestore_api.c', 'namestore_api_monitor.c']
libgnunetpluginnamestore_sqlite_src = ['plugin_namestore_sqlite.c']

gnunetnamestore_src = ['gnunet-namestore.c']
gnunetservicenamestore_src = ['gnunet-service-namestore.c']

configure_file(input : 'namestore.conf.in',
               output : 'namestore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetnamestore = library('gnunetnamestore',
          libgnunetnamestore_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetnamestore_dep = declare_dependency(link_with : libgnunetnamestore)
  libgnunetpluginnamestore_sqlite = library('gnunet_plugin_namestore_sqlite',
          libgnunetpluginnamestore_sqlite_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetidentity_dep,
                         libgnunetsq_dep,
                         libgnunetstatistics_dep,
                         sqlite_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetpluginnamestore_sqlite_dep = declare_dependency(link_with : libgnunetpluginnamestore_sqlite)
  executable ('gnunet-namestore',
              gnunetnamestore_src,
              dependencies: [libgnunetnamestore_dep,
                             libgnunetutil_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetidentity_dep],
              include_directories: [incdir, configuration_inc])
  executable ('gnunet-service-namestore',
              gnunetservicenamestore_src,
              dependencies: [libgnunetnamestore_dep,
                             libgnunetutil_dep,
                             libgnunetnamecache_dep,
                             libgnunetgnsrecord_dep,
                             libgnunetidentity_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetnamestore_src + libgnunetpluginnamestore_sqlite_src + gnunetservicenamestore_src
    gnunet_src += 'namestore/' + p
  endforeach
endif
