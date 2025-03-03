project('gnunet', 'c', license: 'AGPLv3',
        meson_version: '>=1.0.0',
        version: run_command('sh', 'scripts/get_version.sh', check: true).stdout().strip())

version = run_command('sh', 'scripts/get_version.sh', check: true).stdout().strip()
add_project_arguments('-D_GNU_SOURCE', language : 'c')

cc = meson.get_compiler('c')
incdir = include_directories('src/include')
private_config = configuration_data()

# Version
gnunet_version = run_command('sh', 'scripts/get_version.sh', check: true).stdout().strip()

pkgcfgdir = get_option('datadir')/'gnunet'/'config.d'
docdir = get_option('datadir')/'doc'/'gnunet'

install_emptydir(docdir)
install_data('README', 'COPYING', install_dir: docdir)

gnunet_user = false
getent_bin = find_program('getent', '/usr/bin/getent', required : false)
if getent_bin.found()
  gnunet_user = true
  if run_command('getent', 'passwd', 'gnunet', check: false).returncode() != 0
    gnunet_user = false
  endif
  if run_command('getent', 'group', 'gnunet', check: false).returncode() != 0
    gnunet_user = false
  endif
  if run_command('getent', 'group', 'gnunetdns', check: false).returncode() != 0
    gnunet_user = false
  endif
endif


# TODO: Set to true to build a single libgnunet
private_config.set10('HAVE_EXPERIMENTAL', get_option('experimental'))
private_config.set10('ENABLE_MALICIOUS', get_option('malicious'))
private_config.set10('ENABLE_POISONING', get_option('poisoning'))

# FIXME: This is not really used anywhere
private_config.set10('ENABLE_BENCHMARK', get_option('benchmarks'))
private_config.set10('HAVE_BENCHMARKS', get_option('benchmarks'))

private_config.set10('ENABLE_NSE_HISTOGRAM', get_option('nse-histogram'))
logging_opt = get_option('logging')
if logging_opt == 'yes'
  add_project_arguments('-DGNUNET_EXTRA_LOGGING=0', language: 'c')
endif
if logging_opt == 'no'
  add_project_arguments('-DGNUNET_EXTRA_LOGGING=0', language: 'c')
  add_project_arguments('-DGNUNET_CULL_LOGGING=1', language: 'c')
endif
if logging_opt == 'verbose'
  add_project_arguments('-DGNUNET_EXTRA_LOGGING=1', language: 'c')
endif
if logging_opt == 'veryverbose'
  add_project_arguments('-DGNUNET_EXTRA_LOGGING=2', language: 'c')
endif


# Various checks
if cc.has_member ('struct sockaddr_in', 'sin_len', prefix : ['#include <sys/types.h>', '#include <sys/socket.h>', '#include <netinet/in.h>'])
  private_config.set('HAVE_SOCKADDR_IN_SIN_LEN', 1)
endif
if cc.has_member ('struct sockaddr_un', 'sun_len', prefix : ['#include <sys/types.h>', '#include <sys/socket.h>', '#include <sys/un.h>'])
  private_config.set('HAVE_SOCKADDR_UN_SUN_LEN', 1)
endif
if cc.has_member ('struct tm', 'tm_gmtoff', prefix : ['#include <time.h>'])
  private_config.set('HAVE_TM_GMTOFF', 1)
endif

# TODO:
#  - Go through configure.ac and convert all defines/detections
#  - Compile all libs into a single libgnunet

# Gettext
i18n = import('i18n')

gettext_package = 'gnunet'
add_project_arguments('-DGETTEXT_PACKAGE=' + gettext_package, language: 'c')
subdir('po')

private_config.set_quoted('PACKAGE_VERSION', version)
private_config.set_quoted('GNUNET_DEFAULT_INTERFACE', 'en0')
private_config.set_quoted('VCS_VERSION', 'mesonbuild')
private_config.set_quoted('PACKAGE_BUGREPORT', 'bug-gnunet@gnu.org')
add_project_arguments('-DHAVE_CONFIG_H', language : 'c')

# Linker settings
# Compiler settings
add_project_arguments('-fno-strict-aliasing', language : 'c')
if cc.has_argument('-Wno-address-of-packed-member')
  add_project_arguments('-Wno-address-of-packed-member', language : 'c')
endif
if cc.has_argument('-Wno-tautological-constant-out-of-range-compare')
  add_project_arguments('-Wno-tautological-constant-out-of-range-compare', language : 'c')
endif


private_config.set_quoted('build_target', host_machine.system())
if host_machine.system() == 'linux'
  private_config.set('LINUX', 1)
  add_project_link_arguments(['-Wl,--unresolved-symbols=report-all'], language : 'c')
  private_config.set_quoted('GNUNET_DEFAULT_INTERFACE', 'eth0')
elif host_machine.system() == 'darwin'
  private_config.set_quoted('GNUNET_DEFAULT_INTERFACE', 'en0')
  private_config.set('DARWIN', 1)
  add_project_arguments('-DDARWIN', language : 'c')
  add_project_arguments('-D_APPLE_C_SOURCE', language : 'c')
  add_project_arguments('-D__APPLE_USE_RFC_3542', language : 'c')
  add_project_arguments('-fno-common', language : 'c')
  add_project_link_arguments (['-Wl,-no_fixup_chains'], language: 'c')
else
  private_config.set('OTHEROS', 1)
endif


# FIXME: Not all dependencies here yet
ltdl_dep = dependency ('libltdl', required: false)
if not ltdl_dep.found()
  ltdl_dep = cc.find_library('ltdl', required : true)
endif
unistr_dep = dependency('libunistring', required : false)
if not unistr_dep.found()
  unistr_dep = cc.find_library('unistring', required : true)
endif
sqlite_dep = dependency ('sqlite3', version: '>=3.35.0', required : false)
# FIXME for fallbacks, we need to manually check version
if not sqlite_dep.found()
  sqlite_dep = cc.find_library('sqlite3', required : true)
  sqlite_version_check ='''#include <sqlite3.h>
  int main(int argc, char **argv) {
    return (SQLITE_VERSION_NUMBER >= 3035000) ? 0 : 1;
  }
  '''
  if cc.run(sqlite_version_check, name : 'sqlite version check',
            dependencies: sqlite_dep).returncode() != 0
    error('Sqlite version >= 3.35.0 requried')
  endif
endif
curl_dep = dependency('libcurl', version: '>=7.85.0', required : false)
if not curl_dep.found()
  curl_dep = cc.find_library('curl', required : true)
  curl_version_check ='''#include <curl/curl.h>
  int main(int argc, char **argv) {
    return (LIBCURL_VERSION_NUM >= 0x075500) ? 0 : 1;
    }
  '''
  if cc.run(curl_version_check, name : 'cURL version check',
            dependencies: curl_dep).returncode() != 0
    error('cURL version >=7.85.0 required')
  endif
endif
zlib_dep = dependency('zlib', required : false)
if not zlib_dep.found()
  zlib_dep = cc.find_library('zlib', required : true)
endif
mhd_dep = dependency('libmicrohttpd', required : false)
if not mhd_dep.found()
  mhd_dep = cc.find_library('microhttpd', required : true)
endif
mhd2_dep = dependency('libmicrohttpd2', required : false)
if not mhd2_dep.found()
  mhd_dep2 = cc.find_library('microhttpd2', required : false)
endif
json_dep = dependency('jansson', required : false)
if not json_dep.found()
  json_dep = cc.find_library('jansson', required : true)
endif
gcrypt_dep = dependency('libgcrypt', required : false)
if not gcrypt_dep.found()
  gcrypt_dep = cc.find_library('gcrypt', required : true)
endif
lgmp_dep = dependency('libgmp', required : false)
if not lgmp_dep.found()
  lgmp_dep = cc.find_library('gmp', required : true)
endif
gnutls_dep = dependency('libgnutls', required : false)
if not gnutls_dep.found()
  gnutls_dep = cc.find_library('gnutls', required : false)
  if not gnutls_dep.found()
    gnutls_dep = cc.find_library('gnutls-dane', required : true)
  endif
endif
sodium_dep = dependency('libsodium', required : false, version: '>=1.0.18')
if not sodium_dep.found()
  sodium_dep = cc.find_library('sodium', required : true)
  sodium_version_check ='''#include <sodium.h>
  int main(int argc, char **argv) {
    return ((SODIUM_LIBRARY_VERSION_MAJOR > 10) ||
            ((SODIUM_LIBRARY_VERSION_MAJOR == 10) &&
             (SODIUM_LIBRARY_VERSION_MINOR >= 3))) ? 0 : 1;
    }
  '''
  if cc.run(sodium_version_check, name : 'sodium version check',
            dependencies: sodium_dep).returncode() != 0
    error('libsodium version >=1.0.18 required')
  endif
endif
extractor_dep = dependency('libextractor', required : false)
if not extractor_dep.found()
  extractor_dep = cc.find_library('extractor', required : false)
endif
private_config.set10('HAVE_EXTRACTOR', extractor_dep.found())
private_config.set10('HAVE_EXTRACTOR_H', extractor_dep.found())
quic_dep = dependency('libquiche', required : false)
if not quic_dep.found()
  quic_dep = cc.find_library('quiche', required : false)
endif
ngtcp2_crypto_dep = dependency('libngtcp2_crypto_gnutls', required : false)
if not ngtcp2_crypto_dep.found()
  ngtcp2_crypto_dep = cc.find_library('ngtcp2_crypto_gnutls', required : false)
endif
ngtcp2_dep = dependency('libngtcp2', required : false)
if not ngtcp2_dep.found()
  ngtcp2_dep = cc.find_library('ngtcp2', required : false)
endif
nghttp3_dep = dependency('libnghttp3', required : false)
if not nghttp3_dep.found()
  nghttp3_dep = cc.find_library('nghttp3', required : false)
endif
http3_enabled = ngtcp2_dep.found() and ngtcp2_crypto_dep.found() and nghttp3_dep.found()
if http3_enabled
  message ('HTTP3 enabled')
endif
idn_dep = dependency('libidn2', required : false)
if not idn_dep.found()
  idn_dep = cc.find_library('idn2', required : false)
endif
if idn_dep.found()
  private_config.set('HAVE_LIBIDN2', 1)
  private_config.set('HAVE_IDN2_H', 1)
else
  idn_dep = dependency('libidn', required : false)
  if not idn_dep.found()
    idn_dep = cc.find_library('idn', required : true)
    private_config.set('HAVE_LIBIDN', 1)
    private_config.set('HAVE_IDN_H', 1)
  endif
endif
pthread_dep = cc.find_library('pthread', required : false)
if pthread_dep.found()
  private_config.set('HAVE_PTHREAD', 1)
endif

m_dep = cc.find_library('m', required : false)
if m_dep.found()
  private_config.set('HAVE_LIBM', 1)
endif

sock_dep = cc.find_library('socket', required : false)
if sock_dep.found()
  private_config.set('HAVE_LIBSOCKET', 1)
endif

gopt_bin = find_program('getopt', '/usr/bin/getopt', required : false)
if gopt_bin.found()
  private_config.set_quoted('HAVE_GETOPT_BINARY', gopt_bin.full_path())
endif

upnpc_bin = find_program('upnpc', '/usr/bin/upnpc', required: false)
if upnpc_bin.found()
  private_config.set_quoted('UPNPC', upnpc_bin.full_path())
endif

ifconfig_bin = find_program('ifconfig', '/usr/sbin/ifconfig', required : false)
if ifconfig_bin.found()
  private_config.set_quoted('IFCONFIG', ifconfig_bin.full_path())
endif

ip_bin = find_program('ip', '/usr/sbin/ip', required : false)
if ip_bin.found()
  private_config.set_quoted('PATH_TO_IP', ip_bin.full_path())
endif

iptables_bin = find_program('iptables', '/usr/sbin/iptables', required : false)
if iptables_bin.found()
  private_config.set_quoted('IPTABLES', iptables_bin.full_path())
endif
ip6tables_bin = find_program('ip6tables', '/usr/sbin/ip6tables', required : false)
if ip6tables_bin.found()
  private_config.set_quoted('IP6TABLES', ip6tables_bin.full_path())
endif


adduser_bin = find_program('adduser', '/usr/sbin/adduser', required : false)

pkgc_bin = find_program('pkg-config', '/usr/bin/pkg-config', required : false)
if pkgc_bin.found()
  private_config.set('HAVE_PKG_CONFIG', 1)
endif

ssh_bin = find_program('ssh', '/usr/bin/ssh', required : false)
if ssh_bin.found()
  private_config.set('HAVE_SSH_BINARY', 1)
endif

# FIXME we are not doing anything with this right now
sudo_bin = find_program('sudo', '/usr/bin/sudo', required : false)
doas_bin = find_program('doas', '/usr/bin/doas', required : false)

# Optional dependencies

pq_dep = dependency('libpq', required : false)
if not pq_dep.found()
  pq_dep = cc.find_library('pq', required : false)
endif
if pq_dep.found()
  private_config.set('HAVE_POSTGRESQL', 1)
endif
zbar_dep = dependency('libzbar', required : false)
if not zbar_dep.found()
  zbar_dep = cc.find_library('zbar', required : false)
endif
if zbar_dep.found()
  private_config.set('HAVE_ZBAR', 1)
endif
jose_dep = dependency('libjose', required : false)
if not jose_dep.found()
  jose_dep = cc.find_library('jose', required : false)
endif
if jose_dep.found()
  private_config.set('HAVE_JOSE', 1)
endif

## FIXME conversation: pulse/gst detection in configure.ac was obviously
## broken. Needs reconsideration. No idea for now.
pulse_dep = dependency('libpulse', required : false)
if not pulse_dep.found()
  pulse_dep = cc.find_library('pulse', required : false)
endif

opus_dep = dependency('libopus', required : false)
if not opus_dep.found()
  opus_dep = cc.find_library('opus', required : false)
endif

ogg_dep = dependency('libogg', required : false)
if not ogg_dep.found()
  ogg_dep = cc.find_library('ogg', required : false)
endif
gst_dep = dependency('gstreamer-1.0', required : false)
if not gst_dep.found()
  gst_dep = cc.find_library('gstreamer-1.0', required : false)
endif
gst_app_dep = dependency('gstreamer-app-1.0', required : false)
if not gst_app_dep.found()
  gst_app_dep = cc.find_library('gstreamer-app-1.0', required : false)
endif
gst_audio_dep = dependency('gstreamer-audio-1.0', required : false)
if not gst_audio_dep.found()
  gst_audio_dep = cc.find_library('gstreamer-audio-1.0', required : false)
endif

conversation_backend = 'none'
if pulse_dep.found() and opus_dep.found() and ogg_dep.found()
  conversation_backend = 'pulse'
elif gst_dep.found() and gst_app_dep.found() and gst_audio_dep.found()
    conversation_backend = 'gst'
endif
## END conversation

private_config.set_quoted('NEED_LIBGCRYPT_VERSION', '1.6.0')

# NSS
have_nss = false
if cc.check_header('nss.h')
  have_nss = true
endif

# TUN
tun_found = false
if cc.check_header('if_tun.h')
  if cc.has_header_symbol('if_tun.h', 'struct in6_ifreq')
    private_config.set_quoted('IF_TUN_HDR', 'if_tun.h')
    tun_found = true
  endif
endif
if not tun_found and cc.check_header('linux/if_tun.h')
  if cc.has_header_symbol('linux/if_tun.h', 'struct in6_ifreq')
    private_config.set_quoted('IF_TUN_HDR', 'linux/if_tun.h')
    tun_found = true
  endif
endif
if not tun_found and cc.check_header('net/if_tun.h')
  if cc.has_header_symbol('net/if_tun.h', 'struct in6_ifreq')
    private_config.set_quoted('IF_TUN_HDR', 'net/if_tun.h')
    tun_found = true
  endif
endif
if not tun_found and cc.check_header('net/tun/if_tun.h')
  if cc.has_header_symbol('net/tun/if_tun.h', 'struct in6_ifreq')
    private_config.set_quoted('IF_TUN_HDR', 'net/tun/if_tun.h')
    tun_found = true
  endif
endif

# Check for optional libatomic
atomic_dep = dependency('', required: false)
if cc.has_function('__atomic_load_8') == false
  atomic_dep = cc.find_library('atomic', required : true)
endif

# GNUTLS DANE
if cc.check_header('gnutls/dane.h')
  if cc.has_function('dane_verify_crt_raw',
    prefix: '#include <gnutls/dane.h>',
    dependencies: gnutls_dep)
    # FIXME unused in code
    private_config.set('HAVE_GNUTLS_DANE', 1)
  endif
endif
curl_ssl_check ='''#include <curl/curl.h>
  int main(int argc, char **argv) {
    return (CURLSSLSET_OK != curl_global_sslset(CURLSSLBACKEND_GNUTLS, NULL, NULL));
    }
  '''

result = cc.run(curl_ssl_check, name : 'cURL gnutls check',
  dependencies: curl_dep)
private_config.set('curl_gnutls', 0)
if result.returncode() == 0
  private_config.set('curl_gnutls', 1)
endif

if cc.has_function('getloadavg') == false
  error('getloadadv missing')
endif

check_syscalls = [
  ['atoll', '#include<stdlib.h>'],
  ['explicit_bzero', '#include<strings.h>'],
  ['freeifaddrs', '#include<ifaddrs.h>'],
  ['getaddrinfo', '#include<netdb.h>'],
  ['gethostbyname', '#include<netdb.h>'],
  ['gethostbyname2', '#include<netdb.h>'],
  ['getifaddrs', '#include<ifaddrs.h>'],
  ['getpeereid', '#include<unistd.h>'],
  ['getpeerucred', '#include<unistd.h>'],
  ['getresgid', '#include<unistd.h>'],
  ['getrlimit', '#include<sys/resource.h>'],
  ['getrusage', '#include<sys/resource.h>'],
  ['initgroups', '#include<unistd.h>'],
  ['mallinfo2', ''],
  ['malloc_size', ''],
  ['malloc_usable_size', ''],
  ['memset_s', '#include<string.h>'],
  ['mremap', ''],
  ['pipe2', ''],
  ['random', ''],
  ['renameat2', ''],
  ['setresuid', ''],
  ['setrlimit', ''],
  ['srandom', ''],
  ['stat', ''],
  ['stat64', ''],
  ['statfs', ''],
  ['statvfs', ''],
  ['strndup', '#include <string.h>'],
  ['strnlen', '#include <string.h>'],
  ['timegm', ''],
  ['wait4', '']
]

foreach f : check_syscalls
  if cc.has_function(f.get(0), prefix : f.get(1))
    define = 'HAVE_' + f.get(0).underscorify().to_upper()
    private_config.set(define, 1)
  endif
endforeach


check_headers = [
  'arpa/inet.h',
  'byteswap.h',
  'dirent.h',
  'dlfcn.h',
  'endian.h',
  'execinfo.h',
  'fcntl.h',
  'ifaddrs.h',
  'langinfo.h',
  'libintl.h',
  'ltdl.h',
  'mach/mach.h',
  'malloc.h',
  'malloc/malloc.h',
  'malloc/malloc_np.h',
  'math.h',
  'netdb.h',
  'netinet/in.h',
  'netinet/in_systm.h',
  'netinet/ip.h',
  'signal.h',
  'stdatomic.h',
  'sys/endian.h',
  'sys/file.h',
  'sys/ioctl.h',
  'sys/mman.h',
  'sys/mount.h',
  'sys/msg.h',
  'sys/param.h',
  'sys/resource.h',
  'sys/select.h',
  'sys/socket.h',
  'sys/statvfs.h',
  'sys/sysinfo.h',
  'sys/time.h',
  'sys/timeb.h',
  'sys/types.h',
  'sys/ucred.h',
  'sys/vfs.h',
  'ucred.h',
  'vfork.h'
]

foreach h : check_headers
  if cc.check_header(h)
    define = 'HAVE_' + h.underscorify().to_upper()
    message(define)
    private_config.set(define, 1)
  endif
endforeach

configure_file(
  output : 'gnunet_private_config.h',
  configuration : private_config)
configuration_inc = include_directories('.')

cdata = configuration_data()
cdata.merge_from(private_config)

cdata.set('START_ON_DEMAND', 'YES')
if get_option('disable-autostart')
  cdata.set('START_ON_DEMAND', 'NO')
endif
cdata.set('gnunet_version', gnunet_version)
r = run_command('sh', 'scripts/get_version.sh', '--major', check: true)
cdata.set('gnunet_major_version', r.stdout().strip())
r = run_command('sh', 'scripts/get_version.sh', '--minor', check: true)
cdata.set('gnunet_minor_version', r.stdout().strip())
r = run_command('sh', 'scripts/get_version.sh', '--micro', check: true)
cdata.set('gnunet_micro_version', r.stdout().strip())
cdata.set10('enable_experimental', get_option('experimental'))
cdata.set10('extractor', extractor_dep.found())
cdata.set('PKGDATADIRECTORY', get_option('prefix')/get_option('datadir')/'gnunet')
cdata.set('SYSCONFDIR', get_option('prefix')/get_option('sysconfdir'))
cdata.set('UNIXONLY', '#') # FIXME unclear if required still...

pkg = import('pkgconfig')

subdir('scripts')
subdir('src')
subdir('doc')
subdir('contrib')
subdir('data')

meson.add_dist_script('meson-dist-script')

gnunet_prefix = get_option('prefix')/get_option('libdir')

add_test_setup('default', env: ['GNUNET_PREFIX='+gnunet_prefix], exclude_suites: ['perf'], is_default: true)
add_test_setup('full',  env: ['GNUNET_PREFIX='+gnunet_prefix], is_default: false)

summary({'host': host_machine.system(),
  'prefix': get_option('prefix'),
  'compiler': cc.get_id(),
  'libdir': get_option('libdir'),
  'datadir': get_option('datadir'),
  'default interface': private_config.get('GNUNET_DEFAULT_INTERFACE'),
  'PostgreSQL': pq_dep.found(),
  'curl w/ gnutls': (private_config.get('curl_gnutls') == 1),
  'ifconfig': ifconfig_bin.found(),
  'iptables': iptables_bin.found()
  }, section: 'Detected system')

if not gnunet_user
  message('Please make sure NOW to create a user and group \'gnunet\' and additionally a group \'gnunetdns\'. Make sure that \'/var/lib/gnunet\' is owned (and writable) by user \'gnunet\'')
  message('Each user of GNUnet should be added to the \'gnunet\' group')
  if adduser_bin.found() and not gnunet_user
    message(
      '''Create the gnunet user and add users to the gnunetdns group, run:
      # addgroup gnunetdns
      # adduser --system --disabled-login --home /var/lib/gnunet gnunet
    '''
    )
    message(
      '''
    To add users to the gnunet group, run:
      # adduser USERNAME gnunet
    for each of your users, replacing \'USERNAME\' with the respective login name.
    Users may have to login again for the changes to take effect.''')
  endif
endif
