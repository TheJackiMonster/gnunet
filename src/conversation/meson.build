libgnunetconversation_src = ['conversation_api.c', 'conversation_api_call.c']

gnunetserviceconversation_src = ['gnunet-service-conversation.c',
                        'gnunet-service-conversation_resolver.c',
                        'gnunet-service-conversation_interceptor.c']

gnunetconversationproxy_src = ['gnunet-conversation-proxy.c']

configure_file(input : 'conversation.conf.in',
               output : 'conversation.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetconversation_src + gnunetserviceconversation_src
    gnunet_src += 'conversation/' + p
  endforeach
  subdir_done()
endif

libgnunetmicrophone = library('gnunetmicrophone',
        ['microphone.c'],
        soversion: '0.0.0',
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetmicrophone_dep = declare_dependency(link_with : libgnunetmicrophone)
pkg.generate(libgnunetmicrophone, url: 'https://www.gnunet.org',
             description : 'Provides API to access to microphone')

libgnunetspeaker = library('gnunetspeaker',
        ['speaker.c'],
        soversion: '0.0.0',
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetspeaker_dep = declare_dependency(link_with : libgnunetspeaker)
pkg.generate(libgnunetspeaker, url: 'https://www.gnunet.org',
             description : 'Provides API to access to speaker')

libgnunetconversation = library('gnunetconversation',
        libgnunetconversation_src,
        soversion: '0.0.0',
        dependencies: [libgnunetutil_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetgns_dep,
                       libgnunetnamestore_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetconversation_dep = declare_dependency(link_with : libgnunetconversation)
pkg.generate(libgnunetconversation, url: 'https://www.gnunet.org',
             description : 'Provides API to access to conversation')

shared_module('gnunet_plugin_gnsrecord_conversation',
        ['plugin_gnsrecord_conversation.c'],
        dependencies: [libgnunetutil_dep,
                       libgnunetconversation_dep,
                       libgnunetgns_dep,
                       libgnunetgnsrecord_dep,
                       libgnunetidentity_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))

libgnunetconversation_dep = declare_dependency(link_with : libgnunetconversation)
pkg.generate(libgnunetconversation, url: 'https://www.gnunet.org',
             description : 'Provides API to access the GNU Name System')


executable ('gnunet-conversation',
            'gnunet-conversation.c',
            dependencies: [libgnunetconversation_dep,
                           libgnunetgns_dep,
                           libgnunetgnsrecord_dep,
                           libgnunetnamestore_dep,
                           libgnunetspeaker_dep,
                           libgnunetmicrophone_dep,
                           libgnunetidentity_dep,
                           libgnunetutil_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('bindir'))
executable ('gnunet-service-conversation',
            gnunetserviceconversation_src,
            dependencies: [libgnunetconversation_dep,
                           libgnunetspeaker_dep,
                           libgnunetmicrophone_dep,
                           libgnunetidentity_dep,
                           libgnunetcadet_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')
