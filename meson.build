## EXPERIMENTAL --- WORK IN PROGRESS --- USE AT YOUR OWN PERIL --- ##
project('gnunet', 'c', license: 'AGPLv3',
        version: run_command('sh', 'contrib/get_version.sh', check: true).stdout().strip())

compiler = meson.get_compiler('c')
incdir = include_directories('src/include')
cdata = configuration_data()

# Version
r = run_command('sh', 'contrib/get_version.sh', check: true)
cdata.set('gnunet_version', r.stdout().strip())
r = run_command('sh', 'contrib/get_version.sh', '--major', check: true)
cdata.set('gnunet_major_version', r.stdout().strip())
r = run_command('sh', 'contrib/get_version.sh', '--minor', check: true)
cdata.set('gnunet_minor_version', r.stdout().strip())
r = run_command('sh', 'contrib/get_version.sh', '--micro', check: true)
cdata.set('gnunet_micro_version', r.stdout().strip())

pkgcfgdir = get_option('datadir')/'gnunet'/'config.d'

# TODO: Set to true to build a single libgnunet
if get_option('monolith')
  add_project_arguments('-DHAVE_GNUNET_MONOLITH', language: 'c')
endif
cdata.set('enable_experimental', get_option('experimental'))
if get_option('experimental')
  add_project_arguments('-DHAVE_EXPERIMENTAL', language: 'c')
endif

# FIXME
cdata.set('extractor', 0)


# Various checks
if compiler.has_member ('struct sockaddr_in', 'sin_len', prefix : ['#include <sys/types.h>', '#include <sys/socket.h>', '#include <netinet/in.h>'])
  add_project_arguments('-DHAVE_SOCKADDR_IN_SIN_LEN', language: 'c')
endif
if compiler.has_member ('struct sockaddr_un', 'sun_len', prefix : ['#include <sys/types.h>', '#include <sys/socket.h>', '#include <sys/un.h>'])
  add_project_arguments('-DHAVE_SOCKADDR_UN_SUN_LEN', language: 'c')
endif

message('Building on ' + host_machine.system())

# TODO:
#  - Go through configure.ac and convert all defines/detections
#  - Compile all libs into a single libgnunet

# Gettext
i18n = import('i18n')

gettext_package = 'gnunet'
add_project_arguments('-DGETTEXT_PACKAGE=' + gettext_package, language: 'c')
subdir('po')

# FIXME lots still missing
cdata.set_quoted('PACKAGE_VERSION', '0.21.0')
cdata.set_quoted('GNUNET_DEFAULT_INTERFACE', 'en0')
cdata.set_quoted('VCS_VERSION', 'mesonbuild')
add_project_arguments('-DHAVE_CONFIG_H', language : 'c')

# Linker settings
# Compiler settings
add_project_arguments('-fno-strict-aliasing', language : 'c')
if compiler.has_argument('-Wno-address-of-packed-member')
  add_project_arguments('-Wno-address-of-packed-member', language : 'c')
endif
if compiler.has_argument('-Wno-tautological-constant-out-of-range-compare')
  add_project_arguments('-Wno-tautological-constant-out-of-range-compare', language : 'c')
endif

# FIXME static here, were dynamic in configure.ac
cdata.set('UNIXONLY', '#')
cdata.set('JAVAPORT', '#')
cdata.set('START_ON_DEMAND', 'YES')


cdata.set_quoted('build_target', host_machine.system())
if host_machine.system() == 'linux'
  add_project_link_arguments(['-Wl,--unresolved-symbols=report-all'], language : 'c')
  cdata.set_quoted('GNUNET_DEFAULT_INTERFACE', 'eth0')
endif
if host_machine.system() == 'darwin'
  cdata.set_quoted('GNUNET_DEFAULT_INTERFACE', 'en0')
  add_project_arguments('-D_APPLE_C_SOURCE', language : 'c')
  add_project_arguments('-D__APPLE_USE_RFC_3542', language : 'c')
  add_project_arguments('-fno-common', language : 'c')
endif


# FIXME: Not all dependencies here yet
ltdl_dep = compiler.find_library('ltdl', required : true)
unistr_dep = compiler.find_library('unistring', required : true)
sqlite_dep = compiler.find_library('sqlite3', required : true)
curl_dep = dependency('libcurl')
zlib_dep = dependency('zlib')
mhd_dep = dependency('libmicrohttpd')
json_dep = compiler.find_library('jansson', required : true)
gcrypt_dep = dependency('libgcrypt')
gnutls_dep = compiler.find_library('gnutls', required : false)
if gnutls_dep.found() == false
  gnutls_dep = compiler.find_library('gnutls-dane', required : true)
endif

sodium_dep = dependency('libsodium')
cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)
if m_dep.found()
  add_project_arguments('-DHAVE_LIBM', language : 'c')
endif
sock_dep = cc.find_library('socket', required : false)
if sock_dep.found()
  add_project_arguments('-DHAVE_LIBSOCKET', language : 'c')
endif
gopt_bin = find_program('getopt', '/usr/bin/getopt', required : false)
if gopt_bin.found()
  add_project_arguments('-DHAVE_GETOPT_BINARY='+gopt_bin.full_path(), language : 'c')
endif
pkgc_bin = find_program('pkg-config', '/usr/bin/pkg-config', required : false)
if pkgc_bin.found()
  add_project_arguments('-DHAVE_PKG_CONFIG', language : 'c')
endif
ssh_bin = find_program('ssh', '/usr/bin/ssh', required : false)
if ssh_bin.found()
  add_project_arguments('-DHAVE_SSH_BINARY', language : 'c')
endif

idn_dep = dependency('libidn2') # FIXME detect libidn as well
gnunetdeps = [mhd_dep,
              sodium_dep,
              gcrypt_dep,
              curl_dep,
              json_dep,
              zlib_dep,
              sqlite_dep,
              unistr_dep, #dependency('libunistring'),
              ltdl_dep, #dependency('ltdl'),
              idn_dep]

add_project_arguments('-DNEED_LIBGCRYPT_VERSION="1.6.0"', language : 'c')

if compiler.has_header('sys/time.h')
  add_project_arguments('-DHAVE_SYS_TIME_H', language : 'c')
endif
if compiler.has_header('sys/param.h')
  add_project_arguments('-DHAVE_SYS_PARAM_H', language : 'c')
endif

if compiler.has_header('idn2.h')
  add_project_arguments('-DHAVE_LIBIDN2', language : 'c')
  add_project_arguments('-DHAVE_IDN2_H', language : 'c')
endif


# GNUTLS DANE
if compiler.has_header('gnutls/dane.h')
  if compiler.has_function('dane_verify_crt_raw',
                           prefix: '#include <gnutls/dane.h>',
                           dependencies: gnutls_dep)
    add_project_arguments('-DHAVE_GNUTLS_DANE', language : 'c')
  endif
endif
curl_ssl_check ='''#include <curl/curl.h>
  int main(int argc, char **argv) {
    return (CURLSSLSET_OK != curl_global_sslset(CURLSSLBACKEND_GNUTLS, NULL, NULL));
  }
'''
result = compiler.run(curl_ssl_check, name : 'cURL gnutls check',
                      dependencies: curl_dep)
cdata.set('curl_gnutls', 0)
if result.returncode() == 0
  cdata.set('curl_gnutls', 1)
endif

if compiler.has_function('getloadavg') == false
  error('getloadadv missing')
endif
if compiler.has_function('strnlen', prefix : '#include <string.h>')
  cdata.set('HAVE_STRNLEN', 1)
endif
if compiler.has_function('memset_s')
  cdata.set('HAVE_MEMSET_S', 1)
endif
if compiler.has_function('explicit_bzero')
  cdata.set('HAVE_EXPLICIT_BZERO', 1)
endif


configure_file(#input: 'gnunet_private_config.h.in',
               output : 'gnunet_private_config.h',
               configuration : cdata)
configuration_inc = include_directories('.')

subdir('src')
subdir('doc')
subdir('contrib')

meson.add_dist_script('meson-dist-script')
