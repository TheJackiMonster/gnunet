libgnunetfriends_src = ['friends.c']

gnunetdaemontopology_src = ['gnunet-daemon-topology.c']


if gnunet_monolith == false
  libgnunetfriends = library('gnunetfriends',
          libgnunetfriends_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetfriends_dep = declare_dependency(link_with : libgnunetfriends)
  executable ('gnunet-daemon-topology',
              gnunetdaemontopology_src,
              dependencies: [libgnunetfriends_dep,
                             libgnunetutil_dep,
                             libgnunetcore_dep,
                             libgnunetpeerinfo_dep,
                             libgnunetstatistics_dep,
                             libgnunettransport_dep,
                             libgnunetats_dep,
                             libgnunethello_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetfriends_src + gnunetdaemontopology_src
    gnunet_src += 'topology/' + p
  endforeach
endif
