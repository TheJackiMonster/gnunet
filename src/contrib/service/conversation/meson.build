libgnunetconversation_src = ['conversation_api.c', 'conversation_api_call.c']

gnunetserviceconversation_src = ['gnunet-service-conversation.c']

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
endif

libgnunetmicrophone = library('gnunetmicrophone',
        ['microphone.c'],
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetmicrophone_dep = declare_dependency(link_with : libgnunetmicrophone)
pkg.generate(libgnunetmicrophone, url: 'https://www.gnunet.org',
             description : 'Provides API to access to microphone')

libgnunetspeaker = library('gnunetspeaker',
        ['speaker.c'],
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
libgnunetspeaker_dep = declare_dependency(link_with : libgnunetspeaker)
pkg.generate(libgnunetspeaker, url: 'https://www.gnunet.org',
             description : 'Provides API to access to speaker')

libgnunetconversation = library('gnunetconversation',
        libgnunetconversation_src,
        soversion: '0',
        version: '0.0.0',
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
        install_dir: get_option('libdir')/'gnunet')

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
                           libgnunetutil_dep,
                           libgnunetspeaker_dep,
                           libgnunetmicrophone_dep,
                           libgnunetidentity_dep,
                           libgnunetcadet_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

helperrecord_src = ['gnunet-helper-audio-record.c']
helperplayback_src = ['gnunet-helper-audio-record.c']
if conversation_backend == 'gst'
  helperrecord_src = ['gnunet-helper-audio-record-gst.c']
  helperplayback_src = ['gnunet-helper-audio-playback-gst.c']
endif

executable ('gnunet-helper-audio-record',
            helperrecord_src,
            dependencies: [libgnunetconversation_dep,
                           libgnunetutil_dep,
                           libgnunetspeaker_dep,
                           libgnunetmicrophone_dep,
                           gst_dep,
                           gst_app_dep,
                           gst_audio_dep,
                           ogg_dep,
                           pulse_dep,
                           opus_dep
                           ],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

executable ('gnunet-helper-audio-playback',
         helperplayback_src,
          dependencies: [libgnunetconversation_dep,
                         libgnunetutil_dep,
                         libgnunetspeaker_dep,
                         libgnunetmicrophone_dep,
                         gst_dep,
                         gst_app_dep,
                         gst_audio_dep,
                         ogg_dep,
                         pulse_dep,
                         opus_dep
                         ],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir') / 'gnunet' / 'libexec')

testconvapi = executable ('test_conversation_api',
         ['test_conversation_api.c'],
          dependencies: [libgnunetconversation_dep,
                         libgnunetutil_dep,
                         libgnunetidentity_dep,
                         libgnunettesting_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetnamestore_dep,
                         libgnunetspeaker_dep,
                         libgnunetmicrophone_dep,
                         ],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir') / 'gnunet' / 'libexec')

testconvapitwo = executable ('test_conversation_api_twocalls',
         ['test_conversation_api_twocalls.c'],
          dependencies: [libgnunetconversation_dep,
                         libgnunetutil_dep,
                         libgnunetidentity_dep,
                         libgnunettesting_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetnamestore_dep,
                         libgnunetspeaker_dep,
                         libgnunetmicrophone_dep,
                         ],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir') / 'gnunet' / 'libexec')

testconvapireject = executable ('test_conversation_api_reject',
         ['test_conversation_api_reject.c'],
          dependencies: [libgnunetconversation_dep,
                         libgnunetutil_dep,
                         libgnunetidentity_dep,
                         libgnunettesting_dep,
                         libgnunetgnsrecord_dep,
                         libgnunetnamestore_dep,
                         libgnunetspeaker_dep,
                         libgnunetmicrophone_dep,
                         ],
          include_directories: [incdir, configuration_inc],
          install: true,
          install_dir: get_option('libdir') / 'gnunet' / 'libexec')

configure_file(input : 'test_conversation.conf',
               output : 'test_conversation.conf',
               copy: true,
               install: false)

test('test_conversation_api', testconvapi, workdir: meson.current_build_dir(),
     suite: ['conversation', 'contrib'])

test('test_conversation_api_twocalls', testconvapitwo, workdir: meson.current_build_dir(),
     suite: ['conversation', 'contrib'])

test('test_conversation_api_reject', testconvapireject, workdir: meson.current_build_dir(),
     suite: ['conversation', 'contrib'])

