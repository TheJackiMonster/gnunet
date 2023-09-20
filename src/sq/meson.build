libgnunetsq_src = ['sq.c',
                   'sq_exec.c',
                   'sq_prepare.c',
                   'sq_query_helper.c',
                   'sq_result_helper.c']

if gnunet_monolith == false
  libgnunetsq = library('gnunetsq',
          libgnunetsq_src,
          dependencies: [libgnunetutil_dep, sqlite_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetsq_dep = declare_dependency(link_with : libgnunetsq)
else
  foreach p : libgnunetsq_src + gnunetservicesq_src
    gnunet_src += 'sq/' + p
  endforeach
endif
