gnunetpeerinfotool_src = ['gnunet-peerinfo.c', 'gnunet-peerinfo_plugins.c']


if get_option('monolith')
  subdir_done()
endif

executable ('gnunet-peerinfo',
            gnunetpeerinfotool_src,
            dependencies: [libgnunetutil_dep,
                           libgnunetpeerinfo_dep,
                           libgnunettransport_dep,
                           libgnunethello_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
