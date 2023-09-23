libgnunetregex_src = ['regex_api_announce.c',
                     'regex_api_search.c']
libgnunetregexblock_src = ['regex_block_lib.c']

gnunetserviceregex_src = ['gnunet-service-regex.c',
                          'regex_internal_dht.c',
                          'regex_internal.c']

configure_file(input : 'regex.conf.in',
               output : 'regex.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetregex_src + libgnunetregexblock_src + gnunetserviceregex_src
    gnunet_src += 'regex/' + p
  endforeach
  subdir_done()
endif

libgnunetregex = library('gnunetregex',
        libgnunetregex_src,
        soversion: '3.1.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetregex, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the regex service')
libgnunetregex_dep = declare_dependency(link_with : libgnunetregex)
libgnunetregexblock = library('gnunetregexblock',
        libgnunetregexblock_src,
        soversion: '1.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetregexblock_dep = declare_dependency(link_with : libgnunetregexblock)

executable ('gnunet-service-regex',
            gnunetserviceregex_src,
            dependencies: [libgnunetregex_dep, libgnunetutil_dep,
                           libgnunetdht_dep,
                           libgnunetstatistics_dep,
                           libgnunetregex_dep,
                           libgnunetregexblock_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

