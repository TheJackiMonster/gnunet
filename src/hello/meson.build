libgnunethello_src = ['hello.c',
                      'address.c',
                      'hello-ng.c',
                      'hello-uri.c']

gnunethello_src = ['gnunet-hello.c']


if gnunet_monolith == false
  libgnunethello = library('gnunethello',
          libgnunethello_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunethello_dep = declare_dependency(link_with : libgnunethello)
  executable ('gnunet-hello',
              gnunethello_src,
              dependencies: [libgnunethello_dep, libgnunetutil_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunethello_src + gnunethello_src
    gnunet_src += 'hello/' + p
  endforeach
endif
