libgnunetdns_src = ['dns_api.c']
libgnunetpluginblockdns_src = ['plugin_block_dns.c']

gnunetservicedns_src = ['gnunet-service-dns.c']
gnunetdnsredirector_src = ['gnunet-dns-monitor.c']
gnunetdnsmonitor_src = ['gnunet-dns-redirector.c']


if gnunet_monolith == false
  libgnunetdns = library('gnunetdns',
          libgnunetdns_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetdns_dep = declare_dependency(link_with : libgnunetdns)
  libgnunetpluginblockdns = library('gnunet_plugin_block_dns',
          libgnunetpluginblockdns_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetpluginblockdns_dep = declare_dependency(link_with : libgnunetpluginblockdns)
  executable ('gnunet-service-dns',
              gnunetservicedns_src,
              dependencies: [libgnunetdns_dep, libgnunetutil_dep,
                             libgnunetstatistics_dep],
              include_directories: [incdir, configuration_inc])
  executable ('gnunet-dns-monitor',
              gnunetdnsmonitor_src,
              dependencies: [libgnunetdns_dep, libgnunetutil_dep, libgnunetdns_dep],
              include_directories: [incdir, configuration_inc])
  executable ('gnunet-dns-redirector',
              gnunetdnsredirector_src,
              dependencies: [libgnunetdns_dep, libgnunetutil_dep, libgnunetdns_dep],
              include_directories: [incdir, configuration_inc])
else
  foreach p : libgnunetdns_src + gnunetservicedns_src + gnunetdnsmonitor_src + gnunetdnsredirector_src + libgnunetpluginblockdns_src
    gnunet_src += 'dns/' + p
  endforeach
endif
