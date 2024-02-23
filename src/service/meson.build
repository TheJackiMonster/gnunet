# We collect all sources for the 'big' libgnunet when traversing
# the subdirectories.
if get_option('monolith')
  gnunet_src = []
endif

subdir('util')
subdir('statistics')
subdir('arm')
subdir('testing')
subdir('peerstore')
subdir('nat')
subdir('nat-auto')
subdir('transport')
subdir('core')
subdir('nse')
subdir('hostlist')
subdir('topology')
subdir('dns')
subdir('identity')
subdir('namecache')
subdir('namestore')
subdir('datacache')
subdir('datastore')
subdir('dht')
subdir('cadet')
subdir('seti')
subdir('setu')
subdir('regex')
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

# Compile the 'big' libgnunet shared library.
# It must be compiled with HAVE_GNUNET_MONOLITH to enable
# the correct service macros that do not inject main() functions
# to services.
libgnunet = library('gnunet',
                    gnunet_src,
                    dependencies: [
                      mhd_dep,
                      sodium_dep,
                      gcrypt_dep,
                      curl_dep,
                      json_dep,
                      zlib_dep,
                      sqlite_dep,
                      unistr_dep,
                      ltdl_dep,
                      idn_dep,
                      libgnunetutil_dep,
                      libgnunethello_dep,
                      libgnunetjson_dep,
                      libgnunetblock_dep,
                      libgnunetblockgroup_dep,
                      libgnunetregexblock_dep,
                      libgnunetgnsrecord_dep,
                      libgnunetgnsrecordjson_dep,
                      jose_dep,
                      m_dep,
                      pthread_dep,
                      libgnunetcurl_dep],
                    c_args: ['-DHAVE_GNUNET_MONOLITH=1'],
                    include_directories: [incdir, configuration_inc, exitdir])
libgnunet_dep = declare_dependency(link_with : libgnunet)
