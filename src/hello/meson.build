libgnunethello_src = ['hello.c',
                      'address.c',
                      'hello-ng.c',
                      'hello-uri.c']

gnunethello_src = ['gnunet-hello.c']


if get_option('monolith')
  foreach p : libgnunethello_src
    gnunet_src += 'hello/' + p
  endforeach
  subdir_done()
endif

libgnunethello = library('gnunethello',
        libgnunethello_src,
        soversion: '1.0.1',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunethello_dep = declare_dependency(link_with : libgnunethello)
pkg.generate(libgnunethello, url: 'https://www.gnunet.org',
             description : 'Helper library for handling GNUnet HELLO messages')


executable ('gnunet-hello',
            gnunethello_src,
            dependencies: [libgnunethello_dep, libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))

