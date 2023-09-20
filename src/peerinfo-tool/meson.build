gnunetpeerinfotool_src = ['gnunet-peerinfo.c', 'gnunet-peerinfo_plugins.c']


if gnunet_monolith == false
  executable ('gnunet-peerinfo',
              gnunetpeerinfotool_src,
              dependencies: [libgnunetutil_dep,
                             libgnunetpeerinfo_dep,
                             libgnunettransport_dep,
                             libgnunethello_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
endif
