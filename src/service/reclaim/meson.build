libgnunetreclaim_src = ['reclaim_api.c',
                        'reclaim_attribute.c',
                        'reclaim_credential.c']
libgnunetdid_src = ['did_helper.c',
                    'did_core.c']

gnunetservicereclaim_src = ['gnunet-service-reclaim.c',
                        'gnunet-service-reclaim_tickets.c']

configure_file(input : 'reclaim.conf',
               output : 'reclaim.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetreclaim_src + gnunetservicereclaim_src
    gnunet_src += 'reclaim/' + p
  endforeach
endif

libgnunetreclaim = library('gnunetreclaim',
  libgnunetreclaim_src,
  soversion: solibversions['libgnunetreclaim']['soversion'],
  version: solibversions['libgnunetreclaim']['version'],
  install_rpath: get_option('prefix') / get_option('libdir'),
  dependencies: [libgnunetutil_dep,
                 libgnunetidentity_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir'))
libgnunetreclaim_dep = declare_dependency(link_with : libgnunetreclaim)
pkg.generate(libgnunetreclaim, url: 'https://www.gnunet.org',
             description : 'Provides API to access reclaimID')

libgnunetdid = library('gnunetdid',
  libgnunetdid_src,
  soversion: solibversions['libgnunetdid']['soversion'],
  version: solibversions['libgnunetdid']['version'],
  install_rpath: get_option('prefix') / get_option('libdir'),
  dependencies: [libgnunetutil_dep,
                 libgnunetnamestore_dep,
                 libgnunetgnsrecord_dep,
                 libgnunetgns_dep,
                 json_dep,
                 libgnunetidentity_dep],
  include_directories: [incdir, configuration_inc],
  install: true,
  install_dir: get_option('libdir'))
libgnunetdid_dep = declare_dependency(link_with : libgnunetdid)
pkg.generate(libgnunetdid, url: 'https://www.gnunet.org',
             description : 'Provides API to manipulate DID')

executable ('gnunet-service-reclaim',
            gnunetservicereclaim_src,
            dependencies: [libgnunetreclaim_dep,
                           libgnunetutil_dep,
                           libgnunetstatistics_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetgns_dep,
                           libgnunetidentity_dep,
                           libgnunetnamestore_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

