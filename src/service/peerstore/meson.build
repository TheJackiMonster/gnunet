libgnunetpeerstore_src = ['peerstore_api.c',
                          'peerstore_api_monitor.c',
                          'peerstore_common.c']

gnunetservicepeerstore_src = ['gnunet-service-peerstore.c']

configure_file(input : 'peerstore.conf.in',
               output : 'peerstore.conf',
               configuration : cdata,
               install: true,
               install_dir: pkgcfgdir)


if get_option('monolith')
  foreach p : libgnunetpeerstore_src + gnunetservicepeerstore_src
    gnunet_src += 'peerstore/' + p
  endforeach
endif

libgnunetpeerstore = library('gnunetpeerstore',
        libgnunetpeerstore_src,
        soversion: '0',
        version: '0.0.0',
        dependencies: [libgnunetutil_dep, libgnunethello_dep],
        include_directories: [incdir, configuration_inc],
        install: true,
        install_dir: get_option('libdir'))
pkg.generate(libgnunetpeerstore, url: 'https://www.gnunet.org',
             description : 'Provides API for accessing the peerstore service')
libgnunetpeerstore_dep = declare_dependency(link_with : libgnunetpeerstore)

executable ('gnunet-service-peerstore',
            gnunetservicepeerstore_src,
            dependencies: [libgnunetpeerstore_dep,
                           libgnunetutil_dep,
                           libgnunethello_dep],
            include_directories: [incdir, configuration_inc],
            install: true,
            install_dir: get_option('libdir') / 'gnunet' / 'libexec')

testpeerstore_api_iterate = executable ('test_peerstore_api_iterate',
            ['test_peerstore_api_iterate.c'],
            dependencies: [
              libgnunetpeerstore_dep,
              libgnunettesting_dep,
              libgnunetutil_dep
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testpeerstore_api_store = executable ('test_peerstore_api_store',
            ['test_peerstore_api_store.c'],
            dependencies: [
              libgnunetpeerstore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

testpeerstore_api_watch = executable ('test_peerstore_api_watch',
            ['test_peerstore_api_watch.c'],
            dependencies: [
              libgnunetpeerstore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)
testpeerstore_api_perf = executable ('perf_peerstore_store',
            ['perf_peerstore_store.c'],
            dependencies: [
              libgnunetpeerstore_dep,
              libgnunetutil_dep,
              libgnunettesting_dep,
              ],
            include_directories: [incdir, configuration_inc],
            install: false)

configure_file(input : 'test_peerstore_api_data.conf',
               output : 'test_peerstore_api_data.conf',
               copy: true)

test('test_peerstore_api_store', testpeerstore_api_store,
  suite: 'peerstore', workdir: meson.current_build_dir())
test('test_peerstore_api_watch', testpeerstore_api_watch,
  suite: 'peerstore', workdir: meson.current_build_dir())
test('test_peerstore_api_iterate', testpeerstore_api_iterate,
  suite: 'peerstore', workdir: meson.current_build_dir())
test('perf_peerstore_api_store', testpeerstore_api_perf,
  suite: 'peerstore', workdir: meson.current_build_dir())




