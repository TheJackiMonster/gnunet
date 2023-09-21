if get_option('monolith') == true
  gnunet_src = []
endif

subdir('include')
subdir('util')
subdir('nt')
subdir('hello')
subdir('block')
if get_option('monolith') == false
  subdir('arm')
endif
subdir('statistics')
#$(TESTING)')
if json_dep.found()
 subdir('json')
endif
if curl_dep.found()
  subdir('curl')
endif
if get_option('monolith') == false
  subdir('rest')
endif
subdir('peerinfo')
if sqlite_dep.found()
  subdir('sq')
endif
#subdir('$(MYSQL_DIR)')
#subdir('$(POSTGRES_DIR)')
subdir('datacache')
subdir('datastore')
#subdir('template')
subdir('peerstore')
subdir('ats')
subdir('nat')
subdir('nat-auto')
subdir('fragmentation')
subdir('transport')
#subdir('ats-tool')
subdir('core')
##subdir('$(TESTBED)')
subdir('nse')
subdir('dhtu')
subdir('dht')
subdir('hostlist')
subdir('topology')
subdir('regex')
subdir('dns')
subdir('identity')
subdir('gnsrecord')
subdir('namecache')
subdir('namestore')
subdir('peerinfo-tool')
subdir('cadet')
subdir('set')
subdir('seti')
subdir('setu')
subdir('consensus')
#subdir('scalarproduct')
subdir('revocation')
subdir('vpn')
subdir('gns')
subdir('zonemaster')
##subdir('$(CONVERSATION_DIR)')
subdir('fs')
#subdir('exit')
#subdir('pt')
#subdir('secretsharing')
#subdir('reclaim')
#subdir('messenger')
##subdir('$(EXP_DIR)')
#subdir('integration-tests')

if get_option('monolith')
  libgnunet = library('gnunet',
                      gnunet_src,
                      dependencies: gnunetdeps,
                      include_directories: [incdir, configuration_inc, exitdir])
endif
