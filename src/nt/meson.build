libgnunetnt_src = ['nt.c']

if get_option('monolith')
  foreach p : libgnunetnt_src
    gnunet_src += 'nt/' + p
  endforeach
  subdir_done()
endif

libgnunetnt = library('gnunetnt',
        libgnunetnt_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetnt_dep = declare_dependency(link_with : libgnunetnt)
pkg.generate(libgnunetnt, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing GNUnet NT')

