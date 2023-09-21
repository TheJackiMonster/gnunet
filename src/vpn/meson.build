libgnunetvpn_src = ['vpn_api.c']

gnunetservicevpn_src = ['gnunet-service-vpn.c']

exitdir = include_directories('../exit')

configure_file(input : 'vpn.conf.in',
               output : 'vpn.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith') == false
  libgnunetvpn = library('gnunetvpn',
          libgnunetvpn_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetvpn_dep = declare_dependency(link_with : libgnunetvpn)
  executable ('gnunet-service-vpn',
              gnunetservicevpn_src,
              dependencies: [libgnunetvpn_dep,
                             libgnunetutil_dep,
                             libgnunetstatistics_dep,
                             libgnunetregex_dep,
                             libgnunetcore_dep,
                             libgnunetcadet_dep,
                             libgnunetblock_dep],
              include_directories: [incdir, configuration_inc, exitdir])
else
  foreach p : libgnunetvpn_src + gnunetservicevpn_src
    gnunet_src += 'vpn/' + p
  endforeach
endif
