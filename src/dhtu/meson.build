libgnunetplugindhtuip_src = ['plugin_dhtu_ip.c']
libgnunetplugindhtugnunet_src = ['plugin_dhtu_gnunet.c']


if get_option('monolith') == false
  libgnunetplugindhtuip = library('gnunet_plugin_dhtu_ip',
          libgnunetplugindhtuip_src,
          dependencies: libgnunetutil_dep,
          include_directories: [incdir, configuration_inc])
  libgnunetplugindhtuip_dep = declare_dependency(link_with : libgnunetplugindhtuip)
  libgnunetplugindhtugnunet = library('gnunet_plugin_dhtu_gnunet',
          libgnunetplugindhtugnunet_src,
          dependencies: [libgnunetutil_dep,
                         libgnunetats_dep,
                         libgnunetcore_dep,
                         libgnunethello_dep,
                         libgnunetpeerinfo_dep,
                         libgnunetnse_dep,
                         libgnunettransport_dep],
          include_directories: [incdir, configuration_inc])
  libgnunetplugindhtugnunet_dep = declare_dependency(link_with : libgnunetplugindhtugnunet)
else
  foreach p : libgnunetplugindhtuip_src + libgnunetplugindhtugnunet_src
    gnunet_src += 'dhtu/' + p
  endforeach
endif
