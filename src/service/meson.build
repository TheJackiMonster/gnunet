subdir('util')
subdir('arm')
subdir('statistics')
subdir('testing')
subdir('datacache')
subdir('datastore')
subdir('peerstore')
subdir('nat')
subdir('nat-auto')
subdir('transport')
subdir('core')
subdir('nse')
subdir('dhtu')
subdir('dht')
subdir('hostlist')
subdir('regex')
subdir('dns')
subdir('identity')
subdir('namecache')
subdir('namestore')
subdir('cadet')
subdir('seti')
subdir('setu')
subdir('revocation')
subdir('vpn')
subdir('gns')
subdir('zonemaster')
subdir('fs')
subdir('exit')
subdir('pt')
subdir('reclaim')
subdir('messenger')
subdir('rest')

if not get_option('monolith')
  subdir_done()
endif
libgnunet = library('gnunet',
                    gnunet_src,
                    dependencies: [gnunetdeps,
                                   libgnunetutil_dep,
                                   libgnunethello_dep,
                                   libgnunetjson_dep,
                                   libgnunetblock_dep,
                                   libgnunetblockgroup_dep,
                                   libgnunetregexblock_dep,
                                   libgnunetgnsrecord_dep,
                                   libgnunetgnsrecordjson_dep,
                                   jose_dep,
                                   libgnunetcurl_dep],
                    c_args: ['-DHAVE_GNUNET_MONOLITH=1'],
                    include_directories: [incdir, configuration_inc, exitdir])
libgnunet_dep = declare_dependency(link_with : libgnunet)
