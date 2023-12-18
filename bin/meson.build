binfiles = [
  'dosubst.awk',
  'grephdr.sh',
  'grepsrc.sh',
  'pogen.sh',
  'rename.sh',
  'gana_update.sh',
  'sphinx_update.sh',
  ]

foreach f : binfiles
  configure_file(input : f,
    output : f,
    copy: true)
endforeach

