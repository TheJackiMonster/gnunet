libgnunetrevocation_src = ['revocation_api.c']

gnunetservicerevocation_src = ['gnunet-service-revocation.c']


if gnunet_monolith == false
  libgnunetrevocation = library('gnunetrevocation',
          libgnunetrevocation_src,
          dependencies: [libgnunetutil_dep, libgnunetidentity_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetrevocation_dep = declare_dependency(link_with : libgnunetrevocation)
  executable ('gnunet-service-revocation',
              gnunetservicerevocation_src,
              dependencies: [libgnunetrevocation_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetcore_dep,
                             libgnunetsetu_dep,
                             libgnunetidentity_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetrevocation_src + gnunetservicerevocation_src
    gnunet_src += 'revocation/' + p
  endforeach
endif
