libgnunetpq_src = ['pq.c',
                   'pq_connect.c',
                   'pq_eval.c',
                   'pq_event.c',
                   'pq_exec.c',
                   'pq_prepare.c',
                   'pq_query_helper.c',
                   'pq_result_helper.c']

if get_option('monolith')
  foreach p : libgnunetpq_src
    gnunet_src += 'pq/' + p
  endforeach
  subdir_done()
endif

libgnunetpq = library('gnunetpq',
        libgnunetpq_src,
        dependencies: [libgnunetutil_dep, pq_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetpq_dep = declare_dependency(link_with : libgnunetpq)
