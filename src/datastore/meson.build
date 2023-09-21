libgnunetdatastore_src = ['datastore_api.c']

gnunetservicedatastore_src = ['gnunet-service-datastore.c']


if get_option('monolith') == false
  libgnunetdatastore = library('gnunetdatastore',
          libgnunetdatastore_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetstatistics_dep,
                         libgnunetdatacache_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetdatastore_dep = declare_dependency(link_with : libgnunetdatastore)
  executable ('gnunet-service-datastore',
              gnunetservicedatastore_src,
              dependencies: [libgnunetdatastore_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetdatacache_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetdatastore_src + gnunetservicedatastore_src
    gnunet_src += 'datastore/' + p
  endforeach
endif
