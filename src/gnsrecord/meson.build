libgnunetgnsrecord_src = ['gnsrecord.c',
                          'gnsrecord_serialization.c',
                          'gnsrecord_crypto.c',
                          'gnsrecord_misc.c']
libgnunetgnsrecordjson_src = ['json_gnsrecord.c']

if gnunet_monolith == false
  libgnunetgnsrecord = library('gnunetgnsrecord',
          libgnunetgnsrecord_src,
          dependencies: [libgnunetutil_dep,
                         sodium_dep,
                         libgnunetidentity_dep,
                         gcrypt_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetgnsrecord_dep = declare_dependency(link_with : libgnunetgnsrecord)
  libgnunetgnsrecordjson = library('gnunetgnsrecordjson',
          libgnunetgnsrecordjson_src,
          dependencies: [libgnunetutil_dep, libgnunetgnsrecord_dep, json_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetgnsrecordjson_dep = declare_dependency(link_with : libgnunetgnsrecord)
else
  foreach p : libgnunetgnsrecord_src + libgnunetgnsrecordjson_src
    gnunet_src += 'gnsrecord/' + p
  endforeach
endif
