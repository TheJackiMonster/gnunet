libgnunetplugindhtuip_src = ['plugin_dhtu_ip.c']
libgnunetplugindhtugnunet_src = ['plugin_dhtu_gnunet.c']

configure_file(input : 'dhtu.conf',
               output : 'dhtu.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)

if get_option('monolith')
  foreach p : libgnunetplugindhtuip_src + libgnunetplugindhtugnunet_src
    gnunet_src += 'dhtu/' + p
  endforeach
endif

shared_module('gnunet_plugin_dhtu_ip',
          libgnunetplugindhtuip_src,
          dependencies: [libgnunetutil_dep, m_dep],
          include_directories: [incdir, configuration_inc])

shared_module('gnunet_plugin_dhtu_gnunet',
          libgnunetplugindhtugnunet_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetats_dep,
                         m_dep,
                         libgnunetcore_dep,
                         libgnunethello_dep,
                         libgnunetpeerinfo_dep,
                         libgnunetnse_dep,
                         libgnunettransport_dep],
          include_directories: [incdir, configuration_inc])
