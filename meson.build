## EXPERIMENTAL --- WORK IN PROGRESS --- USE AT YOUR OWN PERIL --- ##
project('gnunet', 'c', license: 'AGPLv3')

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


# TODO: Set to true to build a single libgnunet
gnunet_monolith = get_option('monolith')
cdata.set('enable_experimental', get_option('experimental'))

# FIXME
cdata.set('extractor', 0)

message('Building on ' + host_machine.system())

# TODO:
#  - Go through configure.ac and convert all defines/detections
#  - Compile all libs into a single libgnunet

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
gnunetdeps = [mhd_dep,
              gcrypt_dep,
              dependency('libsodium'),
              curl_dep,
              json_dep,
              zlib_dep,
              sqlite_dep,
              unistr_dep, #dependency('libunistring'),
              ltdl_dep, #dependency('ltdl'),
              dependency('libidn2')]

add_project_arguments('-DNEED_LIBGCRYPT_VERSION="1.6.0"', language : 'c')

if compiler.has_header('sys/time.h')
  add_project_arguments('-DHAVE_SYS_TIME_H', language : 'c')
endif

if compiler.has_header('idn2.h')
  add_project_arguments('-DHAVE_LIBIDN2', language : 'c')
  add_project_arguments('-DHAVE_IDN2_H', language : 'c')
endif


# GNUTLS DANE
if compiler.has_header('gnutls/dane.h')
  add_project_arguments('-DHAVE_GNUTLS_DANE', language : 'c')
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
