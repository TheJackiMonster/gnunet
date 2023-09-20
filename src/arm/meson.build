libgnunetarm_src = ['arm_api.c',
                    'arm_monitor_api.c']

gnunetservicearm_src = ['gnunet-service-arm.c']


if gnunet_monolith == false
  libgnunetarm = library('gnunetarm',
          libgnunetarm_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetarm_dep = declare_dependency(link_with : libgnunetarm)
  executable ('gnunet-service-arm',
              gnunetservicearm_src,
              dependencies: [libgnunetarm_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetarm_src + gnunetservicearm_src
    gnunet_src += 'arm/' + p
  endforeach
endif
