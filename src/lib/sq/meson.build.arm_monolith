libgnunetsq_src = ['sq.c',
                   'sq_exec.c',
                   'sq_prepare.c',
                   'sq_query_helper.c',
                   'sq_result_helper.c']

libgnunetsq = library('gnunetsq',
        libgnunetsq_src,
        dependencies: [gcrypt_dep, sodium_dep, libgnunetutil_dep, sqlite_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetsq, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the SQ service')
libgnunetsq_dep = declare_dependency(link_with : libgnunetsq)