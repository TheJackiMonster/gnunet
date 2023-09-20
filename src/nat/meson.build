libgnunetnat_src = ['nat_api.c',
                    'nat_api_stun.c']

gnunetservicenat_src = ['gnunet-service-nat.c',
                        'gnunet-service-nat.c',
                        'gnunet-service-nat_externalip.c',
                        'gnunet-service-nat_stun.c',
                        'gnunet-service-nat_mini.c',
                        'gnunet-service-nat_helper.c']

if gnunet_monolith == false
  libgnunetnat = library('gnunetnat',
          libgnunetnat_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetnat_dep = declare_dependency(link_with : libgnunetnat)
  executable ('gnunet-service-nat',
              gnunetservicenat_src,
              dependencies: [libgnunetnat_dep, libgnunetutil_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetnat_src + gnunetservicenat_src
    gnunet_src += 'nat/' + p
  endforeach
endif
