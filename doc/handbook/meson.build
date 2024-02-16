fs = import('fs')
makeinfo = find_program('makeinfo', native: true, required: false)
sphinx = find_program('sphinx-build', native: true, required: false)

if fs.exists('html')
  install_subdir('html',
                 install_dir: docdir,
                 strip_directory: false)
else
  if sphinx.found()
    sphinxhandbook = custom_target('handbook-html',
      output: 'html',
      command: [sphinx,
              '-M', 'html',
              meson.project_source_root()/'contrib'/'handbook', meson.current_build_dir()],
      install: true,
      install_dir: docdir)
  endif
endif

if fs.exists('texinfo')
  install_data('texinfo'/'gnunet.info',
               install_dir: get_option('infodir'))
else
  if sphinx.found()
    sphinxhandbooktexi = custom_target('handbook-texinfo',
      output: ['texinfo'],
      command: [sphinx,
              '-M', 'texinfo',
              meson.project_source_root()/'contrib'/'handbook', meson.current_build_dir()],
      install: false,
      install_dir: get_option('infodir'))
    custom_target('gnunet.info',
    output: 'gnunet.info',
    depends: sphinxhandbooktexi,
    command: [makeinfo, '--no-split', '--no-headers',
              meson.current_build_dir()/'texinfo'/'gnunet.texi', '-o', '@OUTPUT0@'],
      install: true,
      install_dir: get_option('infodir'))
  endif
endif

