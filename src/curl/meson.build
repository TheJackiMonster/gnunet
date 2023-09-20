libgnunetcurl_src = ['curl.c',
                    'curl_reschedule.c']

if gnunet_monolith == false
  libgnunetcurl = library('gnunetcurl',
          libgnunetcurl_src,
          dependencies: [libgnunetutil_dep, curl_dep, json_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetcurl_dep = declare_dependency(link_with : libgnunetcurl)
else
  foreach p : libgnunetcurl_src
    gnunet_src += 'curl/' + p
  endforeach
endif
