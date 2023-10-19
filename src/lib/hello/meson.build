libgnunethello_src = [#'hello.c',
                      'address.c',
                      'hello-ng.c',
                      'hello-uri.c']

libgnunethello = library('gnunethello',
        libgnunethello_src,
        soversion: '0',
        version: '0.1.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunethello_dep = declare_dependency(link_with : libgnunethello)
pkg.generate(libgnunethello, url: 'https://www.gnunet.org',
             description : 'Helper library for handling GNUnet HELLO messages')


# TNG
#executable ('gnunet-hello',
#            ['gnunet-hello.c'],
#            dependencies: [libgnunethello_dep, libgnunetutil_dep],
#            include_directories: [incdir, configuration_inc],
#            install: true,
#            install_dir: get_option('bindir'))

