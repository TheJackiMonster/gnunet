libgnunetfriends_src = ['friends.c']

gnunetdaemontopology_src = ['gnunet-daemon-topology.c']

configure_file(input : 'topology.conf',
               output : 'topology.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetfriends_src
    gnunet_src += 'topology/' + p
  endforeach
  subdir_done()
endif

libgnunetfriends = library('gnunetfriends',
        libgnunetfriends_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetfriends, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the friends service')
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
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

