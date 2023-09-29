fs = import('fs')

if fs.exists('handbook'/'html')
  install_subdir('handbook/html',
                 install_dir: docdir,
                 strip_directory: false)
else
  sphinx = find_program('sphinx-build', native: true, required: true)

  if sphinx.found()
    sphinxhandbook = custom_target('handbook',
      output: 'handbook',
      command: [sphinx,
              '-b', 'html',
              #'-b', 'info',
              meson.project_source_root()/'contrib'/'sphinx', '@OUTPUT@'/'html'],
      install: true,
      install_dir: docdir)
  endif
endif

#install_data('handbook/texinfo/gnunet.texi',
#             install_dir: get_option('infodir'))
subdir('man')
