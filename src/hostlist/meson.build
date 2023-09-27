gnunetdaemonhostlist_src = ['gnunet-daemon-hostlist.c',
                            'gnunet-daemon-hostlist_server.c',
                            'gnunet-daemon-hostlist_client.c']

configure_file(input : 'hostlist.conf',
               output : 'hostlist.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  subdir_done()
endif
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
            include_directories: [incdir, configuration_inc],
            install:true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
