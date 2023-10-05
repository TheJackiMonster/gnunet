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
  subdir_done()
endif

libgnunettestingdhtu = library('gnunettestingdhtu',
        ['testing_dhtu_cmd_send.c'],
        soversion: '0',
        version: '0.0.0',
        dependencies: [
          libgnunetutil_dep,
          libgnunetarm_dep,
          libgnunettesting_dep
          ],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunettestingdhtu_dep = declare_dependency(link_with : libgnunettestingdhtu)

shared_module('gnunet_plugin_dhtu_ip',
          libgnunetplugindhtuip_src,
          dependencies: [libgnunetutil_dep, m_dep],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')

shared_module('gnunet_plugin_dhtu_gnunet',
          libgnunetplugindhtugnunet_src,
          dependencies: [libgnunetutil_dep,
                         m_dep,
                         libgnunetcore_dep,
                         libgnunethello_dep,
                         libgnunetpeerstore_dep,
                         libgnunetnse_dep,
                         ],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir')/'gnunet')

