gnunetservicetemplate_src = ['gnunet-service-template.c']

configure_file(input : 'template.conf',
               output : 'template.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  subdir_done()
endif

executable ('gnunet-template',
            ['gnunet-template.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-service-template',
            gnunetservicetemplate_src,
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
testtemplateapi = executable ('test_template_api',
            ['test_template_api.c'],
            dependencies: [libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: false)
test('test_template_api', testtemplateapi, workdir: meson.current_source_dir(),
     suite: 'template')
