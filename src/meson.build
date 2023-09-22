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
subdir('json', if_found : json_dep)
subdir('curl', if_found : [curl_dep])
if get_option('monolith') == false
  subdir('rest')
endif
subdir('peerinfo')
subdir('sq', if_found : [sqlite_dep])
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
# TODO
#subdir('exit')
#subdir('pt')
#subdir('secretsharing')
subdir('reclaim')
subdir('messenger')
##subdir('$(EXP_DIR)')
#subdir('integration-tests')

if not get_option('monolith')
  subdir_done()
endif
libgnunet = library('gnunet',
                    gnunet_src,
                    dependencies: gnunetdeps,
                    include_directories: [incdir, configuration_inc, exitdir])
libgnunet_dep = declare_dependency(link_with : libgnunet)

# FIXME here we need to re-enter all that need to link against libgnunet
# For example: dload plugins
# We also need a logic that handles this
# subdir('block')
