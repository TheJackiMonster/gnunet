libgnunetsq_src = ['sq.c',
                   'sq_exec.c',
                   'sq_prepare.c',
                   'sq_query_helper.c',
                   'sq_result_helper.c']

if get_option('monolith')
  foreach p : libgnunetsq_src
    gnunet_src += 'sq/' + p
  endforeach
  subdir_done()
endif

libgnunetsq = library('gnunetsq',
        libgnunetsq_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, sqlite_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetsq, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the SQ service')
libgnunetsq_dep = declare_dependency(link_with : libgnunetsq)

