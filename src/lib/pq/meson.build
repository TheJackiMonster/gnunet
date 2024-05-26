libgnunetpq_src = ['pq.c',
                   'pq_connect.c',
                   'pq_eval.c',
                   'pq_event.c',
                   'pq_exec.c',
                   'pq_prepare.c',
                   'pq_query_helper.c',
                   'pq_result_helper.c']

libgnunetpq = library('gnunetpq',
        libgnunetpq_src,
        soversion: '5',
        version: '5.0.0',
        dependencies: [libgnunetutil_dep, pq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetpq_dep = declare_dependency(link_with : libgnunetpq)

testpq = executable ('test_pq',
          ['test_pq.c'],
          dependencies: [libgnunetutil_dep,
                         pq_dep,
                         libgnunetpq_dep],
          include_directories: [incdir, configuration_inc],
          build_by_default: false,
          install: false)
test('test_pq', testpq,
   workdir: meson.current_build_dir(),
   suite: ['pq'])


