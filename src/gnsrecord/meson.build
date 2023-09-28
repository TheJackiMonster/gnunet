libgnunetgnsrecord_src = ['gnsrecord.c',
                          'gnsrecord_serialization.c',
                          'gnsrecord_crypto.c',
                          'gnsrecord_misc.c']
libgnunetgnsrecordjson_src = ['json_gnsrecord.c']

if get_option('monolith')
  foreach p : libgnunetgnsrecord_src + libgnunetgnsrecordjson_src
    gnunet_src += 'gnsrecord/' + p
  endforeach
  subdir_done()
endif

libgnunetgnsrecord = library('gnunetgnsrecord',
        libgnunetgnsrecord_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       sodium_dep,
                       libgnunetidentity_dep,
                       gcrypt_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetgnsrecord_dep = declare_dependency(link_with : libgnunetgnsrecord)
pkg.generate(libgnunetgnsrecord, url: 'https://www.gnunet.org',
             description : 'Provides API for manipulating GNS records')


libgnunetgnsrecordjson = library('gnunetgnsrecordjson',
        libgnunetgnsrecordjson_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep, json_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetgnsrecordjson_dep = declare_dependency(link_with : libgnunetgnsrecordjson)

