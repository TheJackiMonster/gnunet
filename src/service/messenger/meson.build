libgnunetmessenger_src = ['messenger_api.c',
                          'messenger_api_contact.c',
                          'messenger_api_contact_store.c',
                          'messenger_api_message.c',
                          'messenger_api_message_control.c',
                          'messenger_api_message_kind.c',
                          'messenger_api_list_tunnels.c',
                          'messenger_api_queue_messages.c',
                          'messenger_api_util.c',
                          'messenger_api_handle.c',
                          'messenger_api_room.c']

gnunetservicemessenger_src = ['gnunet-service-messenger.c',
                              'gnunet-service-messenger_service.c',
                              'gnunet-service-messenger_list_handles.c',
                              'gnunet-service-messenger_list_messages.c',
                              'gnunet-service-messenger_member_session.c',
                              'gnunet-service-messenger_member.c',
                              'gnunet-service-messenger_member_store.c',
                              'gnunet-service-messenger_message_handle.c',
                              'gnunet-service-messenger_message_kind.c',
                              'gnunet-service-messenger_message_recv.c',
                              'gnunet-service-messenger_message_send.c',
                              'gnunet-service-messenger_message_state.c',
                              'gnunet-service-messenger_message_store.c',
                              'gnunet-service-messenger_operation_store.c',
                              'gnunet-service-messenger_operation.c',
                              'gnunet-service-messenger_peer_store.c',
                              'gnunet-service-messenger_basement.c',
                              'gnunet-service-messenger_handle.c',
                              'gnunet-service-messenger_room.c',
                              'gnunet-service-messenger_tunnel.c']

configure_file(input : 'messenger.conf.in',
               output : 'messenger.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetmessenger_src + gnunetservicemessenger_src
    gnunet_src += 'messenger/' + p
  endforeach
endif

libgnunetmessenger = library('gnunetmessenger',
        libgnunetmessenger_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetcadet_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetmessenger_dep = declare_dependency(link_with : libgnunetmessenger)
pkg.generate(libgnunetmessenger, url: 'https://www.gnunet.org',
             description : 'Provides API to access the GNUnet Messenger subsystem')

executable ('gnunet-service-messenger',
            gnunetservicemessenger_src,
            dependencies: [libgnunetmessenger_dep,
                           libgnunetutil_dep,
                           libgnunetidentity_dep,
                           libgnunetcadet_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

