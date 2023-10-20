libgnunetdns_src = ['dns_api.c']

gnunetservicedns_src = ['gnunet-service-dns.c']
gnunetdnsredirector_src = ['gnunet-dns-monitor.c']
gnunetdnsmonitor_src = ['gnunet-dns-redirector.c']

configure_file(input : 'dns.conf.in',
               output : 'dns.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetdns_src + gnunetservicedns_src
    gnunet_src += 'dns/' + p
  endforeach
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

executable ('gnunet-service-dns',
            gnunetservicedns_src,
            dependencies: [libgnunetdns_dep, libgnunetutil_dep,
                           libgnunetstatistics_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir')/'gnunet'/'libexec')
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

  test_dns = configure_file(input : 'test_gnunet_dns.sh',
                 output : 'test_gnunet_dns.sh',
                 copy: true)

  test('test_gnunet_gns', test_dns, suite: 'dns', workdir: meson.current_build_dir())
endif
