libgnunetcurl_src = ['curl.c',
                    'curl_reschedule.c']

if get_option('monolith')
  foreach p : libgnunetcurl_src
    gnunet_src += 'curl/' + p
  endforeach
  subdir_done()
endif

libgnunetcurl = library('gnunetcurl',
        libgnunetcurl_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, curl_dep, json_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetcurl_dep = declare_dependency(link_with : libgnunetcurl)

