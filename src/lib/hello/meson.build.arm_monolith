libgnunethello_src = ['hello-uri.c']

libgnunethello = library('gnunethello',
        libgnunethello_src,
        dependencies: [gcrypt_dep, sodium_dep,libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunethello_dep = declare_dependency(link_with : libgnunethello)
pkg.generate(libgnunethello, url: 'https://www.gnunet.org',
             description : 'Helper library for handling GNUnet HELLO messages')