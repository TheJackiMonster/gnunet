libgnunetdht_src = ['dht_api.c']

libgnunetpluginblockdht_src = ['plugin_block_dht.c']

gnunetservicedht_src = ['gnunet-service-dht.c',
                        'gnunet-service-dht_datacache.c',
                        'gnunet-service-dht_neighbours.c',
                        'gnunet-service-dht_routing.c']

configure_file(input : 'dht.conf.in',
               output : 'dht.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith') == false
  libgnunetdht = library('gnunetdht',
          libgnunetdht_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetdht_dep = declare_dependency(link_with : libgnunetdht)
  libgnunetpluginblockdht = library('gnunet_plugin_block_dht',
          libgnunetpluginblockdht_src,
          dependencies: [libgnunetutil_dep,
                         libgnunethello_dep,
                         libgnunetblock_dep,
                         libgnunetblockgroup_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetpluginblockdht_dep = declare_dependency(link_with : libgnunetpluginblockdht)
  executable ('gnunet-service-dht',
              gnunetservicedht_src,
              dependencies: [libgnunetdht_dep, libgnunetutil_dep,
                             libgnunetblock_dep,
                             libgnunetdatacache_dep,
                             libgnunetstatistics_dep,
                             libgnunetblockgroup_dep,
                             libgnunethello_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetdht_src + gnunetservicedht_src
    gnunet_src += 'dht/' + p
  endforeach
endif
