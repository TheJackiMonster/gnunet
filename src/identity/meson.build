libgnunetidentity_src = ['identity_api.c',
                         'identity_api_lookup.c',
                         'identity_api_suffix_lookup.c']

gnunetserviceidentity_src = ['gnunet-service-identity.c']


if get_option('monolith') == false
  libgnunetidentity = library('gnunetidentity',
          libgnunetidentity_src,
          dependencies: [libgnunetutil_dep, sodium_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetidentity_dep = declare_dependency(link_with : libgnunetidentity)
  executable ('gnunet-service-identity',
              gnunetserviceidentity_src,
              dependencies: [libgnunetidentity_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetidentity_src + gnunetserviceidentity_src
    gnunet_src += 'identity/' + p
  endforeach
endif
