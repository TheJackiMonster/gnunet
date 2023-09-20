## EXPERIMENTAL --- WORK IN PROGRESS --- USE AT YOUR OWN PERIL --- ##
project('gnunet', 'c', license: 'AGPLv3', version: '0.21.0')
compiler = meson.get_compiler('c')
incdir = include_directories('src/include')
cdata = configuration_data()

# TODO: Set to true to build a single libgnunet
gnunet_monolith = false

message('Building on ' + host_machine.system())

# TODO:
#  - Go through configure.ac and convert all defines/detections
#  - Compile all libs into a single libgnunet

# FIXME lots still missing
cdata.set_quoted('PACKAGE_VERSION', '0.21.0')
cdata.set_quoted('GNUNET_DEFAULT_INTERFACE', 'en0')
cdata.set_quoted('VCS_VERSION', 'mesonbuild')
add_project_arguments('-DHAVE_CONFIG_H', language : 'c')


# FIXME: Not all dependencies here yet
ltdl_dep = compiler.find_library('ltdl', required : true)
unistr_dep = compiler.find_library('unistring', required : true)
sqlite_dep = compiler.find_library('sqlite3', required : true)
curl_dep = dependency('libcurl')
zlib_dep = dependency('zlib')
mhd_dep = dependency('libmicrohttpd')
json_dep = compiler.find_library('jansson', required : true)
gnunetdeps = [mhd_dep,
              dependency('libgcrypt'),
              dependency('libsodium'),
              curl_dep,
              json_dep,
              zlib_dep,
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


if compiler.has_function('strnlen', prefix : '#include <string.h>')
  # function exists, do whatever is required.
  add_project_arguments('-DHAVE_STRNLEN', language : 'c')
endif

configure_file(#input: 'gnunet_private_config.h.in',
               output : 'gnunet_private_config.h',
               configuration : cdata)
configuration_inc = include_directories('.')

subdir('src')
