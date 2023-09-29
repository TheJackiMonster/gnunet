libgnunetdns_src = ['dns_api.c']
libgnunetpluginblockdns_src = ['plugin_block_dns.c']

gnunetservicedns_src = ['gnunet-service-dns.c']
gnunetdnsredirector_src = ['gnunet-dns-monitor.c']
gnunetdnsmonitor_src = ['gnunet-dns-redirector.c']

configure_file(input : 'dns.conf.in',
               output : 'dns.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetdns_src + gnunetservicedns_src + libgnunetpluginblockdns_src
    gnunet_src += 'dns/' + p
  endforeach
  subdir_done()
endif

libgnunetdns = library('gnunetdns',
        libgnunetdns_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: libgnunetutil_dep,
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetdns_dep = declare_dependency(link_with : libgnunetdns)
pkg.generate(libgnunetdns, url: 'https://www.gnunet.org',
             description : 'Provides API to access GNUnet\'s DNS service (to intercept and manipulate DNS queries)')

shared_module('gnunet_plugin_block_dns',
        libgnunetpluginblockdns_src,
        dependencies: [libgnunetutil_dep, libgnunetblockgroup_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir')/'gnunet')

executable ('gnunet-service-dns',
            gnunetservicedns_src,
            dependencies: [libgnunetdns_dep, libgnunetutil_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-dns-monitor',
            gnunetdnsmonitor_src,
            dependencies: [libgnunetdns_dep, libgnunetutil_dep, libgnunetdns_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
executable ('gnunet-dns-redirector',
            gnunetdnsredirector_src,
            dependencies: [libgnunetdns_dep, libgnunetutil_dep, libgnunetdns_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')

if host_machine.system() == 'linux'
  executable ('gnunet-helper-dns',
              ['gnunet-helper-dns.c'],
              dependencies: [libgnunetdns_dep, libgnunetutil_dep, libgnunetdns_dep],
              include_directories: [incdir, configuration_inc],
              install: true,
              install_dir: get_option('libdir')/'gnunet'/'libexec')
endif
