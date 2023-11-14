gnunetservicezonemaster_src = ['gnunet-service-zonemaster.c']

configure_file(input : 'zonemaster.conf.in',
               output : 'zonemaster.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : gnunetservicezonemaster_src
    gnunet_src += 'zonemaster/' + p
  endforeach
endif

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
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

