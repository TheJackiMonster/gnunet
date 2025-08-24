install_data(
    [
        'netjail' / 'netjail_core.sh',
        'netjail' / 'netjail_exec.sh',
        'netjail' / 'netjail_start.sh',
        'netjail' / 'netjail_start_new.sh',
        'netjail' / 'netjail_stop.sh',
        'netjail' / 'netjail_test_master.sh',
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
    'check_codespell.sh', 'dictionary.txt'
]

foreach f : binfiles
    configure_file(input: f, output: f, copy: true)
endforeach

