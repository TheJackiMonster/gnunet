gnunetservicezonemaster_src = ['gnunet-service-zonemaster.c']


if gnunet_monolith == false
  executable ('gnunet-service-zonemaster',
              gnunetservicezonemaster_src,
              dependencies: [
                             libgnunetutil_dep,
                             libgnunetdht_dep,
                             libgnunetidentity_dep,
                             libgnunetstatistics_dep,
                             libgnunetnamecache_dep,
                             libgnunetnamestore_dep,
                             libgnunetgnsrecord_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : gnunetservicezonemaster_src
    gnunet_src += 'zonemaster/' + p
  endforeach
endif
