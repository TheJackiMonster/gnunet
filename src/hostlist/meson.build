gnunetdaemonhostlist_src = ['gnunet-daemon-hostlist.c',
                            'gnunet-daemon-hostlist_server.c',
                            'gnunet-daemon-hostlist_client.c']


if gnunet_monolith == false
  executable ('gnunet-daemon-hostlist',
              gnunetdaemonhostlist_src,
              dependencies: [libgnunetutil_dep,
                             libgnunetcore_dep,
                             libgnunethello_dep,
                             libgnunetpeerinfo_dep,
                             libgnunetstatistics_dep,
                             libgnunettransport_dep,
                             mhd_dep,
                             curl_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : gnunetdaemonhostlist_src
    gnunet_src += 'hostlist/' + p
  endforeach
endif
