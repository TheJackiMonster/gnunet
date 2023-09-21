libgnunetpeerinfo_src = ['peerinfo_api.c',
                         'peerinfo_api_notify.c']

gnunetservicepeerinfo_src = ['gnunet-service-peerinfo.c']


if get_option('monolith') == false
  libgnunetpeerinfo = library('gnunetpeerinfo',
          libgnunetpeerinfo_src,
          dependencies: [libgnunetutil_dep, libgnunethello_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetpeerinfo_dep = declare_dependency(link_with : libgnunetpeerinfo)
  executable ('gnunet-service-peerinfo',
              gnunetservicepeerinfo_src,
              dependencies: [libgnunetpeerinfo_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunethello_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetpeerinfo_src + gnunetservicepeerinfo_src
    gnunet_src += 'peerinfo/' + p
  endforeach
endif
