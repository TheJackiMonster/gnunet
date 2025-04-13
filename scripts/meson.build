install_data(
    [
        'netjail' / 'netjail_core.sh',
        'netjail' / 'netjail_start.sh',
        'netjail' / 'netjail_stop.sh',
        'netjail' / 'topo.sh',
    ],
    install_dir: get_option('datadir') / 'gnunet',
)

#install_data('xdg-scheme-handler'/'gnunet-uri.desktop',
#             install_dir: get_option('datadir')/'applications')

binfiles = [
    'dosubst.awk',
    'grephdr.sh',
    'grepsrc.sh',
    'pogen.sh',
    'rename.sh',
    'gana_update.sh',
]

foreach f : binfiles
    configure_file(input: f, output: f, copy: true)
endforeach

