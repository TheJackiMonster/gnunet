if get_option('monolith')
  subdir_done()
endif

executable ('gnunet-ats',
            ['gnunet-ats.c'],
            dependencies: [libgnunetats_dep, libgnunetutil_dep,
                           libgnunettransport_dep,
                           libgnunetnt_dep,
                           libgnunethello_dep
                          ],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

