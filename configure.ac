# This file is part of GNUnet.
# (C) 2001--2023 GNUnet e.V.
#
# GNUnet is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# GNUnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL3.0-or-later
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ([2.69])
AC_INIT([gnunet],[m4_esyscmd_s(sh scripts/get_version.sh)],[bug-gnunet@gnu.org])

gnunet_version=m4_esyscmd_s(sh scripts/get_version.sh)
gnunet_major_version=m4_esyscmd_s(sh scripts/get_version.sh --major)
gnunet_minor_version=m4_esyscmd_s(sh scripts/get_version.sh --minor)
gnunet_micro_version=m4_esyscmd_s(sh scripts/get_version.sh --micro)

AC_SUBST([gnunet_version])
AC_SUBST([gnunet_major_version])
AC_SUBST([gnunet_minor_version])
AC_SUBST([gnunet_micro_version])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_HEADERS([gnunet_private_config.h])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([tar-ustar])
AM_SILENT_RULES([yes])

# maybe use AC_USE_SYSTEM_EXTENSIONS?
AH_TOP([#define _GNU_SOURCE 1])

AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
PKG_PROG_PKG_CONFIG([0.29.2])

LT_INIT([disable-static dlopen])

AS_IF([test "x$enable_shared" = "xno"],
  [AC_MSG_ERROR([GNUnet works only with shared libraries, sorry])])

AS_AUTOTOOLS_ALTERNATE

AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_UNALIGNED_64_ACCESS

# Helper to check cflags for compiler
# CC_CHECK_CFLAGS(FLAG, [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]])
AC_DEFUN([CC_CHECK_CFLAGS_SILENT],
  [AC_CACHE_VAL([AS_TR_SH([cc_cv_cflags_$1])],
     [ac_save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $1 -Werror"
      AC_LINK_IFELSE([AC_LANG_SOURCE([int main() { return 0; }])],
                     [eval "AS_TR_SH([cc_cv_cflags_$1])='yes'"],
                     [eval "AS_TR_SH([cc_cv_cflags_$1])='no'"])
      CFLAGS="$ac_save_CFLAGS"])
   AS_IF([eval test "x$]AS_TR_SH([cc_cv_cflags_$1])[" = "xyes"],
         [$2],
         [$3])
])dnl

# Check for FLAG and append it to CFLAGS if supported
# CC_CHECK_CFLAG_APPEND(FLAG, [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]])
AC_DEFUN([CC_CHECK_CFLAG_APPEND],
  [AC_CACHE_CHECK([if $CC supports $1],
     [AS_TR_SH([cc_cv_cflags_$1])],
     [CC_CHECK_CFLAGS_SILENT([$1])])
   AS_IF([eval test "x$]AS_TR_SH([cc_cv_cflags_$1])[" = "xyes"],
         [CFLAGS="$CFLAGS $1"; $2],
         [$3])
])dnl

# Workaround for GCC not doing the proper thing when using a '-Wno' flag.
# Works like CC_CHECK_CFLAG_APPEND except that the '-Wno' prefix is omitted
# (e.g. '-Wno-foo' becomes 'foo')
AC_DEFUN([CC_CHECK_CFLAG_WNO_APPEND],
  [AC_CACHE_CHECK([if $CC supports -Wno-$1],
     [AS_TR_SH([cc_cv_cflags__W$1])],
     [CC_CHECK_CFLAGS_SILENT([-W$1])])
   AS_IF([eval test "x$]AS_TR_SH([cc_cv_cflags__W$1])[" = "xyes"],
         [CFLAGS="$CFLAGS -Wno-$1"; $2],
         [$3])
])dnl

# Use no-strict-aliasing only if the compiler supports it
CC_CHECK_CFLAG_APPEND([-fno-strict-aliasing])

# We make heavy use of these, gcc 9 gives warnings so disable them.
CC_CHECK_CFLAG_WNO_APPEND([address-of-packed-member])
CC_CHECK_CFLAG_WNO_APPEND([tautological-constant-out-of-range-compare])

OLD_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,--unresolved-symbols=report-all"

AS_CASE(["$host_os"],
  [*darwin*|*rhapsody*|*macosx*],
  [AC_DEFINE([DARWIN],[1],[Define to 1 if this is an Apple Darwin system])
   CPPFLAGS="-D_APPLE_C_SOURCE $CPPFLAGS"
   CFLAGS="-fno-common -D__APPLE_USE_RFC_3542 $CFLAGS"
   LDFLAGS="$OLD_LDFLAGS"
   build_target="darwin"
   DEFAULT_INTERFACE="\"en0\""
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
   AC_CHECK_LIB([intl], [gettext])],
  [linux*],
  [AC_DEFINE([LINUX],[1],[Define to 1 if this is a system with a Linux kernel])
   build_target="linux"
   DEFAULT_INTERFACE="\"eth0\""
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
   AC_PATH_XTRA
  ],
  [*freebsd*],
  [CFLAGS="-D_THREAD_SAFE $CFLAGS"
   build_target="freebsd"
   DEFAULT_INTERFACE="\"lo0\""
   xbsd="yes"
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*openbsd*],
  [AC_DEFINE([OPENBSD],[1],[Define to 1 if this is an OpenBSD system])
   # libc needs to be linked explicitly
   LDFLAGS="$OLD_LDFLAGS -lc"
   # and PIC has to be enabled
   CFLAGS="-fPIC $CFLAGS"
   build_target="openbsd"
   DEFAULT_INTERFACE="\"lo0\""
   xbsd="yes"
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*netbsd*],
  [build_target="netbsd"
   DEFAULT_INTERFACE="\"lo0\""
   xbsd="yes"
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*solaris*],
  [AC_DEFINE([SOLARIS],[1],[Define to 1 if this is a Solaris system])
   AC_DEFINE([_REENTRANT],[1],[Needed with Solaris or errno does not work])
   AC_CHECK_LIB([resolv], [res_init])
   AC_CHECK_LIB([rt], [nanosleep])
   build_target="solaris"
   DEFAULT_INTERFACE="\"eth0\""
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*arm-linux*],
  [AC_DEFINE([LINUX],[1],[Define to 1 if this is a system with a Linux kernel])
   CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
   build_target="linux"
   DEFAULT_INTERFACE="\"eth0\""
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [gnu*],
  [AC_DEFINE([GNU],[1],[Define to 1 if this is a GNU system])
   build_target="gnu"
   DEFAULT_INTERFACE="\"eth0\""
   UNIXONLY="#"
  ],
  [AC_DEFINE([OTHEROS],[1],[Define to 1 if this is some strange OS])
   DEFAULT_INTERFACE="\"eth0\""
  ])

AC_DEFINE_UNQUOTED([GNUNET_DEFAULT_INTERFACE], [$DEFAULT_INTERFACE],
  [The default choice for the name of the first network interface])
AC_SUBST([DEFAULT_INTERFACE])

# Disable TCP-based IPC on system supporting UNIX domain sockets
AC_SUBST([UNIXONLY])

AC_MSG_CHECKING([for build target])
AM_CONDITIONAL([DARWIN], [test "$build_target" = "darwin"])
AM_CONDITIONAL([SOLARIS], [test "$build_target" = "solaris"])
AM_CONDITIONAL([XNETBSD], [test "$build_target" = "netbsd"])
AM_CONDITIONAL([XFREEBSD], [test "$build_target" = "freebsd"])
AM_CONDITIONAL([OPENBSD], [test "$build_target" = "openbsd"])
AM_CONDITIONAL([XBSD], [test "x$bsd" = "xyes"])
AM_CONDITIONAL([LINUX], [test "$build_target" = "linux"])
AM_CONDITIONAL([GNU], [test "$build_target" = "gnu"])
AC_MSG_RESULT([$build_target])

AS_IF([test "$build_target" = "darwin"],
      [AC_MSG_WARN([The VPN application cannot be compiled on your system])])

AC_SUBST([build_target])

# Other checks for standard libraries
AC_SEARCH_LIBS([gethostbyname], [nsl ws2_32])
AC_SEARCH_LIBS([memchr],[],
               [AC_DEFINE([HAVE_MEMCHR],[1],
                          [Define to 1 if memchr is supported])],
               [])
AC_SEARCH_LIBS([memset_s],[],
               [AC_DEFINE([HAVE_MEMSET_S],[1],
                          [Define to 1 if memset_s is supported])],
               [])
AC_SEARCH_LIBS([explicit_bzero],[],
               [AC_DEFINE([HAVE_EXPLICIT_BZERO],[1],
                          [Define to 1 if explicit_bzero is supported])],
               [])

AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([m], [log])
AC_CHECK_FUNCS([getloadavg])

AC_CHECK_PROG([GETOPT_BINARY], [getopt], [true], [false])
AM_CONDITIONAL([HAVE_GETOPT_BINARY], [$GETOPT_BINARY])

AC_CHECK_PROGS([PKG_CONFIG], [pkgconf pkg-config], [false])
AM_CONDITIONAL([HAVE_PKG_CONFIG], [test "x$PKG_CONFIG" != "xfalse"])

AC_CHECK_PROG([SSH_BINARY], [ssh], [true], [false])
AM_CONDITIONAL([HAVE_SSH_BINARY], [$SSH_BINARY])

AC_MSG_CHECKING([for SSH key])
AS_IF([ssh -D 12345 -o "BatchMode Yes" -o "UserKnownHostsFile /tmp/gnunet_test_cosks_ssh_garbage" -o "StrictHostKeyChecking no" 127.0.0.1 echo -n 2>/dev/null],
      [has_ssh_key=yes],
      [has_ssh_key=no])
AM_CONDITIONAL([HAVE_SSH_KEY], [test "x$has_ssh_key" = "xyes"])
AC_MSG_RESULT([$has_ssh_key])

AS_IF([test -f /tmp/gnunet_test_cosks_ssh_garbage],
      [rm -f /tmp/gnunet_test_cosks_ssh_garbage])

AM_PATH_PYTHON([3.4],,[:])
AC_SUBST([PYTHON])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != ':'])

AC_ARG_WITH([perl],
            [AS_HELP_STRING([--with-perl=PATH], [Look for Perl in PATH])],
            [AS_CASE([$withval],
             [no], [AC_MSG_ERROR([Perl is required])],
             [yes], [AC_PATH_PROG([PERL], [perl])],
             [AC_PATH_PROG([PERL], [perl], [], ["$withval"])])],
            [AC_PATH_PROG([PERL], [perl])])
AC_SUBST([PERL])
AM_CONDITIONAL([HAVE_PERL], [test -x "$PERL"])
AS_IF([test -x "$PERL"],
      [AC_DEFINE([HAVE_PERL], [1], [Define to 1 if perl is available])],
      [AC_DEFINE([HAVE_PERL], [0], [Define to 1 if perl is available])])

AWK_BINARY="$AWK"
AC_SUBST([AWK_BINARY])
AM_CONDITIONAL([HAVE_AWK], [test -x "$AWK_BINARY"])
AS_IF([test -x "$AWK_BINARY"],
      [AC_DEFINE([HAVE_AWK], [1], [Define to 1 if awk is available])],
      [AC_DEFINE([HAVE_AWK], [0], [Define to 1 if awk is available])])

# check for some LaTeX packages used by gnunet-bcd
CHECK_LATEX_PACKAGE([TikZ], [tikz])
CHECK_LATEX_PACKAGE([QR Code], [qrcode])
CHECK_LATEX_PACKAGE([Labels], [labels])
AM_CONDITIONAL([HAVE_PDFLATEX], [test "x$PDFLATEX_BINARY" != "xno"])

AC_ARG_WITH([gnunet-logread],
            [AS_HELP_STRING([--with-gnunet-logread], [Install gnunet-logread])],
            [logread=yes],
            [logread=no])
AS_IF([test "x$logread" = "xyes"],
      [AM_CONDITIONAL([GNUNET_LOGREAD], [true])
       AC_DEFINE([GNUNET_LOGREAD], [1],
                 [Define to 1 if gnunet-logread is available])],
      [AM_CONDITIONAL([GNUNET_LOGREAD], [false])
       AC_DEFINE([GNUNET_LOGREAD], [0],
                 [Define to 1 if gnunet-logread is available])])

# iptables is a soft requirement to run tests
AC_PATH_TARGET_TOOL([IPTABLES_BINARY], [iptables], [false])
AS_IF([test "x$IPTABLES_BINARY" = "xfalse"],
      [AS_IF([test -x "/sbin/iptables"],
             [IPTABLES_BINARY="/sbin/iptables"],
             [AS_IF([test -x "/usr/sbin/iptables"],
                    [IPTABLES_BINARY="/usr/sbin/iptables"])])])

AS_IF([test "x$IPTABLES_BINARY" != "xfalse"],
      [AC_DEFINE_UNQUOTED([IPTABLES], ["$IPTABLES_BINARY"], [Path to iptables])],
      [AC_MSG_WARN([iptables not found])])

# also check for ip6tables
AC_PATH_TARGET_TOOL([IP6TABLES_BINARY], [ip6tables], [false])
AS_IF([test "x$IP6TABLES_BINARY" = "xfalse"],
      [AS_IF([test -x "/sbin/ip6tables"],
             [IP6TABLES_BINARY="/sbin/ip6tables"],
             [AS_IF([test -x "/usr/sbin/ip6tables"],
                    [IP6TABLES_BINARY="/usr/sbin/ip6tables"])])])

AS_IF([test "x$IP6TABLES_BINARY" != "xfalse"],
      [AC_DEFINE_UNQUOTED([IP6TABLES], ["$IP6TABLES_BINARY"],
                          [Path to ip6tables])],
      [AC_MSG_WARN([ip6tables not found])])

# also check for ip
AC_PATH_TARGET_TOOL([IP_BINARY], [ip], [false])
AS_IF([test "x$IP_BINARY" = "xfalse"],
      [AS_IF([test -x "/sbin/ip"],
             [IP_BINARY="/sbin/ip"],
             [AS_IF([test -x "/usr/sbin/ip"],
                    [IP_BINARY="/usr/sbin/ip"])])])

AS_IF([test "x$IP_BINARY" != "xfalse"],
      [AC_DEFINE_UNQUOTED([PATH_TO_IP], ["$IP_BINARY"], [Path to ip])],
      [AC_MSG_WARN([ip not found])])

# locate ifconfig
AC_PATH_TARGET_TOOL([IFCONFIG_BINARY], [ifconfig], [false])
AS_IF([test "x$IFCONFIG_BINARY" = "xfalse"],
      [AS_IF([test -x "/sbin/ifconfig"],
             [IFCONFIG_BINARY="/sbin/ifconfig"],
             [AS_IF([test -x "/usr/sbin/ifconfig"],
                    [IFCONFIG_BINARY="/usr/sbin/ifconfig"])])])

AS_IF([test "x$IFCONFIG_BINARY" != "xfalse"],
      [AC_DEFINE_UNQUOTED([IFCONFIG], ["$IFCONFIG_BINARY"], [Path to ifconfig])],
      [AC_MSG_WARN([ifconfig not found])])

AC_PATH_PROG([MSG_USER_SETUP], [adduser], [false])

# test if the 'gnunet' user and groups exist
getent passwd gnunet > /dev/null
HAVE_GNUNET_USER=$?
getent group gnunet > /dev/null
AS_IF([test x$? != x0],
      [HAVE_GNUNET_USER=1])
getent group gnunetdns > /dev/null
AS_IF([test x$? != x0],
      [HAVE_GNUNET_USER=1])

AC_PATH_TARGET_TOOL([SYSCTL_BINARY], [sysctl], [false])
AS_IF([test "x$SYSCTL_BINARY" = "xfalse"],
      [AS_IF([test -x "/sbin/sysctl"],
             [SYSCTL_BINARY="/sbin/sysctl"],
             [AS_IF([test -x "/usr/sbin/sysctl"],
                    [SYSCTL_BINARY="/usr/sbin/sysctl"])])])

AS_IF([test "x$SYSCTL_BINARY" != "xfalse"],
      [AC_DEFINE_UNQUOTED([SYSCTL], ["$SYSCTL_BINARY"], [Path to sysctl])],
      [AC_MSG_WARN([sysctl not found])])

# (mini)upnpc is a soft runtime requirement
AC_PATH_TARGET_TOOL([UPNPC_BINARY], [upnpc], [false])
AS_IF([test "x$UPNPC_BINARY" != "x$false"],
      [AC_DEFINE_UNQUOTED([UPNPC], ["$UPNPC_BINARY"], [Path to upnpc binary])],
      [AC_MSG_WARN([upnpc binary not found])])

# the following tools might use a flag to specify their path or non-default
# name (e.g. a versioned string instead of simply the program name)

# checkbashisms
AC_CHECK_PROGS([CHECKBASHISMS_BINARY], [checkbashisms checkbashisms.pl], [false])
AM_CONDITIONAL([HAVE_CHECKBASHISMS], [test "x$CHECKBASHISMS_BINARY" != "xfalse"])

# uncrustify
AC_CHECK_PROG([UNCRUSTIFY_BINARY], [uncrustify], [true], [false])
AM_CONDITIONAL([HAVE_UNCRUSTIFY_BINARY], [$UNCRUSTIFY_BINARY])

# yapf
# check only the 'yapf' name for now
AC_CHECK_PROGS([YAPF_BINARY], [yapf], [false])
AM_CONDITIONAL([HAVE_YAPF_BINARY], [test "x$YAPF_BINARY" != "xfalse"])

AC_CHECK_MEMBER([struct tm.tm_gmtoff],
                [AC_DEFINE([HAVE_TM_GMTOFF], [1],
                           [Define to 1 if struct tm has the tm_gmtoff member])],
                [],
                [#include <time.h>])

# "save" libs; only those libs found so far will be
# linked against _everywhere_.  For the others, we
# will be more selective!
SAVE_LIBS=$LIBS

have_addrinfo_a=0
AC_CHECK_LIB([anl], [getaddrinfo_a],
             [have_addrinfo_a=1
              AC_DEFINE([HAVE_GETADDRINFO_A], [1],
                        [Define to 1 if getaddrinfo_a is supported])])
AM_CONDITIONAL([HAVE_GETADDRINFO_A], [test "x$have_addrinfo_a" = "x1"])

# libgcrypt
gcrypt=0
gcrypt_api=1
gcrypt_version=1.6.0
AM_PATH_LIBGCRYPT(["$gcrypt_api:$gcrypt_version"], [gcrypt=1])
AC_CHECK_DECLS([gcry_mpi_set_opaque_copy], [], [], [[#include <gcrypt.h>]])

AS_IF([test "$gcrypt" = "0"],
      [AC_MSG_ERROR([[You need libgcrypt to build this program.
At least version $gcrypt_version (API $gcrypt_api) is required.]])])

AC_DEFINE_UNQUOTED([NEED_LIBGCRYPT_VERSION], ["$gcrypt_version"],
                   [Required libgcrypt version])

AC_CHECK_HEADER([if_tun.h],
  [AC_DEFINE([IF_TUN_HDR], ["if_tun.h"],
             [How to include if_tun.h])
   AC_CHECK_DECLS([struct in6_ifreq], [], [],
                  [[#include <if_tun.h>]])],
  [AC_CHECK_HEADER([linux/if_tun.h],
     [AC_DEFINE([IF_TUN_HDR], ["linux/if_tun.h"],
                [How to include if_tun.h])
      AC_CHECK_DECLS([struct in6_ifreq], [], [],
                     [[#include <linux/if_tun.h>]])],
     [AC_CHECK_HEADER([net/if_tun.h],
        [AC_DEFINE([IF_TUN_HDR], ["net/if_tun.h"],
                   [How to include if_tun.h])
         AC_CHECK_DECLS([struct in6_ifreq], [], [],
                        [[#include <net/if_tun.h>]])],
        [AC_CHECK_HEADER([net/tun/if_tun.h],
           [AC_DEFINE([IF_TUN_HDR], ["net/tun/if_tun.h"],
                      [How to include if_tun.h])
            AC_CHECK_DECLS([struct in6_ifreq], [], [],
                           [[#include <net/tun/if_tun.h>]])])])])])

# Should documentation be built?
AC_ARG_ENABLE([documentation],
              [AS_HELP_STRING([--disable-documentation],
                              [do not build the documentation])],
              [documentation=${enableval}],
              [documentation=yes])

AC_CHECK_PROG([DOXY_BINARY], [doxygen], [true], [false])
AM_CONDITIONAL([HAVE_DOXY_BINARY], [$DOXY_BINARY])

AM_CONDITIONAL([DOCUMENTATION], [test "x$documentation" = "xyes"])

AC_CHECK_PROGS([MANDOC_BINARY], [mandoc], [false])
AM_CONDITIONAL([HAVE_MANDOC], [test "x$MANDOC_BINARY" != "xfalse"])

# check if only the documentation should be build
AC_ARG_ENABLE([documentation-only],
  [AS_HELP_STRING([--enable-documentation-only],
                  [build only the documentation])],
  [AS_IF([test "x${enableval}" = "xno"],
     [documentation_only="0"],
     [documentation_only="1"])],
  [documentation_only="0"])
AC_DEFINE_UNQUOTED([DOCUMENTATION_ONLY], [$documentation_only],
                   [Define to 1 if only documentation is being built])
AM_CONDITIONAL([DOCUMENTATION_ONLY], [test "x$documentation_only" = "x1"])

# check if man pages should be included
AC_ARG_ENABLE([include-manpages],
  [AS_HELP_STRING([--disable-include-manpages],
                  [do not include man pages during installation])],
  [AS_IF([test "x${enableval}" = "xno"],
     [include_man="0"],
     [include_man="1"])],
  [include_man="1"])
AC_DEFINE_UNQUOTED([INCLUDE_MANPAGES], [$include_man],
                   [Define to 1 if man pages are included])
AM_CONDITIONAL([INCLUDE_MANPAGES], [test "x$include_man" = "x1"])

# Hardening options
AC_ARG_ENABLE([gcc-hardening],
  [AS_HELP_STRING([--enable-gcc-hardening], [enable compiler security checks])],
  [AS_IF([test "x$enableval" = "xyes"],
     [CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all"
      CFLAGS="$CFLAGS -fwrapv -fPIE -Wstack-protector"
      CFLAGS="$CFLAGS --param ssp-buffer-size=1"
      LDFLAGS="$LDFLAGS -pie"])])

AC_ARG_ENABLE([linker-hardening],
  [AS_HELP_STRING([--enable-linker-hardening], [enable linker security options])],
  [AS_IF([test "x$enableval" = "xyes"],
     [LDFLAGS="$LDFLAGS -z relro -z now"])])

AC_ARG_ENABLE([sanitizer],
  [AS_HELP_STRING([--enable-sanitizer],
                  [enable address and undefined behaviour sanitizers])],
  [AS_IF([test "x$enableval" = "xyes"],
         [CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer"])])

# Logging
extra_logging=GNUNET_NO
AC_ARG_ENABLE([logging],
  [AS_HELP_STRING([--enable-logging@<:@=value@:>@],
     [enable logging calls; possible values: yes,no,verbose,veryverbose (default yes)])],
  [AS_CASE([$enableval],
           [yes],
           [extra_logging=GNUNET_NO],
           [no],
           [extra_logging=GNUNET_NO
            AC_DEFINE([GNUNET_CULL_LOGGING], [1],
                      [Define to 1 to cull all logging calls])],
           [verbose],
           [extra_logging=GNUNET_YES],
           [veryverbose], [extra_logging=\(GNUNET_YES+1\)],
           [extra_logging=GNUNET_NO])])
AC_DEFINE_UNQUOTED([GNUNET_EXTRA_LOGGING], [$extra_logging],
                   [Define to 1 if extra logging is enabled, 2 for very verbose logging])

AC_ARG_ENABLE([poisoning],
  [AS_HELP_STRING([--enable-poisoning],
                  [enable poisoning of freed memory (good for debugging)])],
  [enable_poisoning=${enableval}],
  [enable_poisoning=missing])

AS_IF([test "x$enable_poisoning" = "xmissing"],
      [AS_IF([test "x$extra_logging" != "xGNUNET_NO"],
             [enable_poisoning=yes],
             [enable_poisoning=no])])

AS_IF([test "x$enable_poisoning" = "xyes"],
      [AC_DEFINE([ENABLED_POISONING], [1],
                 [Define to 1 if freed memory is poisoned])],
      [AC_DEFINE([ENABLED_POISONING], [0],
                 [Define to 1 if freed memory is poisoned])])

AS_IF([test "$build" = "$target"],
  [AC_MSG_CHECKING([for a working HMAC])
   AC_LANG_PUSH([C])
   LIBS="$LIBS $LIBGCRYPT_LIBS"
   CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
   AC_RUN_IFELSE(
     [AC_LANG_PROGRAM([#include <gcrypt.h>],
        [[gcry_md_hd_t mac;
unsigned char data[] = {
  0xbf, 0x16, 0x6e, 0x46, 0x3a, 0x6c, 0xf3, 0x93, 0xa7, 0x72,
  0x11, 0xa1, 0xdc, 0x0b, 0x07, 0xdb, 0x1a, 0x5e, 0xd9, 0xb9, 0x81, 0xbe,
  0xea, 0xe4, 0x31, 0x5f, 0x24, 0xff, 0xfe, 0x50, 0x8a, 0xde
};

unsigned char key[] = { 0xfc, 0x62, 0x76, 0x35 };

unsigned char result[] = {
  0xa2, 0xb, 0x1, 0xd9, 0xc0, 0x8b, 0x5a, 0x12, 0x80,
  0xd5, 0x50, 0x12, 0x8e, 0xd0, 0x5b, 0xb6, 0x5c, 0x87, 0x24, 0xe2, 0xd0,
  0xd2, 0xaf, 0x63, 0xae, 0xd1, 0xd6, 0x64, 0x14, 0xe3, 0x6e, 0x61, 0x5b,
  0xd, 0xba, 0x17, 0x7d, 0xd3, 0x10, 0xb1, 0x37, 0x41, 0x91, 0x7d, 0xeb,
  0x1, 0x4d, 0x71, 0xe8, 0x59, 0x71, 0x42, 0x8e, 0xd6, 0xf3, 0x29, 0x3b,
  0x90, 0xf2, 0xd1, 0xaf, 0x65, 0x1e, 0xb3
};

if (!gcry_check_version (GCRYPT_VERSION))
{
  return 1;
}

gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

if (gcry_md_open(&mac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != GPG_ERR_NO_ERROR)
{
  return 2;
}

gcry_md_setkey (mac, key, sizeof (key));
gcry_md_write (mac, data, sizeof (data));

if (memcmp(gcry_md_read (mac, 0),
           result,
           gcry_md_get_algo_dlen (gcry_md_get_algo (mac))) != 0)
{
  return 3;
}

gcry_md_close (mac);]])],
     [AC_MSG_RESULT([yes])],
     [AC_MSG_RESULT([no])
      RESULT=$?
      AS_CASE([$RESULT],
              [1],
              [AC_MSG_FAILURE([libgcrypt header version does not match library])],
              [2],
              [AC_MSG_FAILURE([HMAC test failed])],
              [3],
              [AC_MSG_FAILURE([HMAC test vector does not match. This is a known problem with libgcrypt 1.2.2 on Windows and it's fixed in 1.4.6])],
              [])],
     [AC_MSG_RESULT([cross compiling, test skipped])])
   AC_LANG_POP([C])])

dnl Helper function to shorten the amount of repeated code
dnl It will create a --with-<lib> option for configure.
dnl
dnl CHECK_WITH_LIB(LIBNAME, FUNC, HEADER, DEFINE-SYM)
dnl LIBNAME is the name of a library without the 'lib' prefix, e.g. 'bluetooth'
dnl for 'libbluetooth'.
dnl DEFINE-SYM is a symbol to define using AC_DEFINE; it will be set to 1 if the
dnl library is available, 0 otherwise.
dnl
dnl The variable LIBNAME (that is, the identifier passed as the first argument)
dnl is kept with the result: 0 if not available, 1 if available.
dnl For example: CHECK_WITH_LIB(foo, ...) will generate $foo.
AC_DEFUN([CHECK_WITH_LIB],
[AC_ARG_WITH([$1],
   [AS_HELP_STRING([--with-][$1][=PFX], [base of lib][$1][ installation])],
   [AS_CASE([$withval],
      [no],
      [eval "AS_TR_SH([$1])=0"],
      [yes],
      [CHECK_LIBHEADER([m4_translit([$1], [a-z], [A-Z])],
         [$1], [$2], [$3],
         [eval "AS_TR_SH([$1])=1"],
         [eval "AS_TR_SH([$1])=0"])],
      [CHECK_LIBHEADER([m4_translit([$1], [a-z], [A-Z])],
         [$1], [$2], [$3],
         [eval "AS_TR_SH([$1])=1"],
         [eval "AS_TR_SH([$1])=0"],
         [-L${withval}/lib],
         [-I${withval}/include])
       AS_IF([test "x$][AS_TR_SH([$1])][" = "x1"],
         [EXT_LIB_PATH="-L${withval}/lib $EXT_LIB_PATH"])])],
    [CHECK_LIBHEADER([m4_translit([$1], [a-z], [A-Z])],
         [$1], [$2], [$3],
         [eval "AS_TR_SH([$1])=1"],
         [eval "AS_TR_SH([$1])=0"])])

 AM_CONDITIONAL([$4], [test "x$][AS_TR_SH([$1])][" = "x1"])
 AC_DEFINE_UNQUOTED([$4], [$][AS_TR_SH([$1])], [Define to 1 if available])
])dnl

# check for libbluetooth
CHECK_WITH_LIB([bluetooth],
               [ba2str],
               [bluetooth/bluetooth.h],
               [HAVE_LIBBLUETOOTH])

# check for libzbar
CHECK_WITH_LIB([zbar], [zbar_processor_create], [zbar.h], [HAVE_ZBAR])

# check for libpng library
# this check is for an optional feature of gnunet-qr.
# the PNG format was chosen mostly arbitrarilyy: while it's true that more
# modern formats exists that can be used in stead of PNG, it's also true that
# it's more common for systems to ship with libpng than other codecs; also, a
# black-or-white picture of squares is one of the cases where PNG shines the
# most, so the advantages of other formats becomes less important.
AS_IF([test "x$zbar" = "x1"],
      [CHECK_WITH_LIB([png], [png_create_read_struct], [png.h], [HAVE_PNG])],
      [AM_CONDITIONAL([HAVE_PNG], [false])
       AC_DEFINE([HAVE_PNG], [0], [Define to 1 if libpng is available])])

# check for libpabc
CHECK_WITH_LIB([pabc], [pabc_new_ctx], [pabc/pabc.h], [HAVE_PABC])

# check for jansson
CHECK_WITH_LIB([jansson], [json_loads], [jansson.h], [HAVE_JANSSON])
AS_IF([test "x$jansson" = "x0"],
  [AC_MSG_ERROR([GNUnet requires jansson])])

# check for jose
CHECK_WITH_LIB([jose], [jose_jwk_gen], [jose/jose.h], [HAVE_JOSE])
AS_IF([test "x$jose" = "x0"],
  [AC_MSG_WARN([reclaimID OpenID Connect plugin requires jose])])

# check for libpulse (pulseaudio)
CHECK_WITH_LIB([pulse], [pa_stream_peek], [pulse/simple.h], [HAVE_PULSE])

# check for libopus
# Note: this might need to be expanded if a more detailed check is needed.
# For example, before CHECK_WITH_LIB was created, it used to look for
# "OPUS_SET_GAIN" in libopus
CHECK_WITH_LIB([opus], [opus_decode_float], [opus/opus.h], [HAVE_OPUS])

# check for libogg
CHECK_WITH_LIB([ogg], [ogg_stream_flush_fill], [ogg/ogg.h], [HAVE_OGG])

PKG_CHECK_MODULES([GST],
  [glib-2.0 gobject-2.0 gstreamer-1.0 gstreamer-app-1.0 gstreamer-audio-1.0],
  [gst=1],
  [gst=0])

# check if conversation can be built and how
AC_MSG_CHECKING([for conversation feature set to build])
AS_IF([test "x$pulse" != "x1" || test "x$opus" != "x1" || test "x$ogg" != "x1"],
  [AS_IF([test "x$gst" != "x1"],
     [conversation_backend="none"
      AM_CONDITIONAL([BUILD_PULSE_HELPERS], [false])
      AM_CONDITIONAL([BUILD_GST_HELPERS], [false])
      AM_CONDITIONAL([BUILD_EXPERIMENTAL_HELPERS], [false])],
     [conversation_backend="gst"
      AM_CONDITIONAL([BUILD_PULSE_HELPERS], [false])
      AM_CONDITIONAL([BUILD_GST_HELPERS], [true])
      AM_CONDITIONAL([BUILD_EXPERIMENTAL_HELPERS], [false])])],
  [conversation_backend="pulse"
   AM_CONDITIONAL([BUILD_PULSE_HELPERS], [true])
   AM_CONDITIONAL([BUILD_GST_HELPERS], [false])
   AM_CONDITIONAL([BUILD_EXPERIMENTAL_HELPERS], [false])])

AM_CONDITIONAL([BUILD_CONVERSATION], [test "x$conversation_backend" != "xnone"])
AC_MSG_RESULT([$conversation_backend])

# NOTE: If we find libcurl-gnutls here we set LIBCURL to -lcurl-gnutls
# This affects the LIBCURL_CHECK_CONFIG call below as it takes LIBCURL into
# account when checking for curl.
LIBCURL="-lcurl"
AC_CHECK_LIB([curl-gnutls],
             [curl_easy_getinfo],
             [LIBCURL="-lcurl-gnutls"])

LIBCURL_CHECK_CONFIG([], [7.85.0], [],
                     [AC_MSG_ERROR([cURL must have a version >= 7.85.0])])

OLD_LIBS=$LIBS
LIBS="$LIBS $LIBCURL"
AC_RUN_IFELSE(
     [AC_LANG_PROGRAM([[#include <curl/curl.h>]],
                      [[return (CURLSSLSET_OK != curl_global_sslset(CURLSSLBACKEND_GNUTLS, NULL, NULL));]])],
                    [curl_gnutls=1],
                    [AC_MSG_WARN([cURL does not have GnuTLS backend])
                     curl_gnutls=0])
LIBS=$OLD_LIBS
AM_CONDITIONAL([HAVE_GNUTLS_CURL], [test "x$curl_gnutls" = "x1"])
AC_SUBST([curl_gnutls])

# Even if curl is found, we check for this constant in order to determine
# if we can use this feature.
AC_CHECK_HEADER([curl/curl.h],
                [AC_CHECK_DECLS([CURLINFO_TLS_SSL_PTR],
                                [],
                                [AC_MSG_ERROR([cURL must support CURLINFO_TLS_SSL_PTR])],
                                [[#include <curl/curl.h>]])])
# libatomic
AC_SEARCH_LIBS([__atomic_load_8], [atomic],
               [have_libatomic=1
                AC_DEFINE([HAVE_LIBATOMIC], [1],
                          [Define to 1 if libatomic is external])])
AM_CONDITIONAL([HAVE_LIBATOMIC], [test "x$have_libatomic" = "x1"])

# check for nss
AC_CHECK_HEADERS([nss.h], [nss=true], [nss=false])
AS_IF([test "x$nss" = "xfalse"],
      [AM_CONDITIONAL([HAVE_GLIBCNSS], [false])
       AC_MSG_WARN([NSS plugin will not be build])],
      [AC_CHECK_DECL([NSS_STATUS_UNAVAIL],
         [AM_CONDITIONAL([HAVE_GLIBCNSS], [true])],
         [AM_CONDITIONAL([HAVE_GLIBCNSS], [false])
          AC_MSG_WARN([NSS plugin will not be built])],
         [[#include <nss.h>]])])

# test for kvm and kstat (for CPU stats under BSD/Solaris)
AC_CHECK_LIB([kvm], [kvm_open])
AC_CHECK_LIB([kstat], [kstat_open])

# check for libsodium version >= 1.0.18
libsodium=0
CHECK_WITH_LIB([sodium], [crypto_core_ed25519_scalar_mul], [sodium.h], [HAVE_SODIUM])
AS_IF([test "x$sodium" = "x0"],
  [AC_MSG_ERROR([GNUnet requires libsodium >= 1.0.18])])

# check for libextractor
CHECK_WITH_LIB([extractor],
               [EXTRACTOR_plugin_add_defaults],
               [extractor.h],
               [HAVE_LIBEXTRACTOR])
AS_IF([test "x$extractor" = "x0"],
      [AC_MSG_RESULT([GNU libextractor not found, some features disabled])])

# check for cloudflare-quiche
CHECK_WITH_LIB([quiche],
               [quiche_header_info],
               [quiche.h],
               [HAVE_QUICHE])
AS_IF([test "x$quiche" = "x0"],
      [AC_MSG_RESULT([cloudflare-quiche not found, some features disabled])])

# check for libltdl
CHECK_WITH_LIB([ltdl], [lt_dlopenext], [ltdl.h], [HAVE_LTDL])
AS_IF([test "x$ldtl" = "x0"],
      [AC_MSG_RESULT([libltdl (from GNU libtool) is required])])

# check for libidn, first version 2 and if not found, version 1
# if both are missing throw an error as libidn is required
AC_ARG_WITH([libidn],
  [AS_HELP_STRING([--with-libidn=PFX], [base of libidn/libidn2 installation])],
  [libidn=${withval}],
  [libidn=yes])

AS_IF([test "x$libidn" = "xno"],
      [AC_MSG_ERROR([GNUnet requires libidn or libidn2])])

AS_IF([test "x$libidn" = "xyes"],
  [AC_CHECK_HEADERS([idn2.h],
     [libidn_version="2"],
     [AC_CHECK_HEADERS([idn2/idn2.h],
                       [libidn_version="2"],
                       [libidn_version="0"])])],
  [LDFLAGS="-L$libidn/lib $LDFLAGS"
   CPPFLAGS="-I$libidn/include $CPPFLAGS"
   AC_CHECK_HEADERS([idn2.h],
     [libidn_version="2"],
     [AC_CHECK_HEADERS([idn2/idn2.h],
                       [libidn_version="2"],
                       [libidn_version="0"])])])

AS_IF([test "x$libidn_version" = "x0"],
  [AS_IF([test "x$libidn" = "xyes"],
     [AC_CHECK_HEADERS([idna.h],
        [libidn_version="1"],
        [AC_CHECK_HEADERS([idn/idna.h],
                          [libidn_version="1"]
                          [libidn_version="2"])])],
     [LDFLAGS="-L$libidn/lib $LDFLAGS"
      CPPFLAGS="-I$libidn/include $CPPFLAGS"
      AC_CHECK_HEADERS([idna.h],
        [libidn_version="2"],
        [AC_CHECK_HEADERS([idn/idna.h],
                          [libidn_version="2"],
                          [libidn_version="0"])])])])

AS_IF([test "x$libidn_version" = "x0"],
  [AC_MSG_ERROR([GNUnet requires libidn or libidn2])])

AS_IF([test "x$libidn_version" = "x2"],
  [AC_CHECK_LIB([idn2], [idn2_to_unicode_8z8z], [libidn_ok=yes], [libidn_ok=no])],
  [AC_CHECK_LIB([idn], [idna_to_ascii_8z], [libidn_ok=yes], [libidn_ok=no])])

AS_IF([test "x$libidn_ok" = "xno"],
  [AC_MSG_ERROR([GNUnet requires libidn or libidn2])])

AM_CONDITIONAL([HAVE_LIBIDN], [test "x$libidn_version" = "x1"])
AM_CONDITIONAL([HAVE_LIBIDN2], [test "x$libidn_version" = "x2"])
AS_IF([test "x$libidn_version" = "x2"],
  [AC_DEFINE([HAVE_LIBIDN2], [1], [Define to 1 if libidn2 is available])],
  [AC_DEFINE([HAVE_LIBIDN], [1], [Define to 1 if libidn is available])])

# check for zlib
AC_ARG_WITH([zlib],
  [AS_HELP_STRING([--with-zlib=PFX], [base of zlib installation])],
  [zlib=${withval}],
  [zlib=yes])

AS_IF([test "x$zlib" = "xno"], [AC_MSG_ERROR([GNUnet requires zlib])])

AS_IF([test "x$zlib" = "xyes"],
  [AC_CHECK_HEADER([zlib.h],
     [AC_CHECK_LIB([z], [compress2], [zlib_ok=1], [zlib_ok=0])],
     [zlib_ok=0])],
  [LDFLAGS="-L$zlib/lib $LDFLAGS"
   CPPFLAGS="-I$zlib/include $CPPFLAGS"
   AC_CHECK_HEADER([zlib.h],
     [AC_CHECK_LIB([z], [compress2], [zlib_ok=1], [zlib_ok=0])],
     [zlib_ok=0])])

AS_IF([test "x$zlib_ok" = "x0"], [AC_MSG_ERROR([GNUnet requires zlib])])
AS_IF([test "x$zlib" = "xyes"],
  [Z_CFLAGS=""
   Z_LIBS="-lz"],
  [Z_CFLAGS="-I${zlib}/include"
   Z_LIBS="-L${zlib}/lib -lz"])
AC_SUBST([Z_CFLAGS])
AC_SUBST([Z_LIBS])

AM_CONDITIONAL([HAVE_ZLIB], [test "x$zlib_ok" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_ZLIB], [$zlib_ok], [Define to 1 if zlib is available])

# check for iconv
AM_ICONV

# check for libunistring
CHECK_WITH_LIB([unistring], [u16_strstr], [unistr.h], [HAVE_UNISTRING])
AS_IF([test "x$unistring" = "x0"],
  [AC_MSG_ERROR([GNUnet requires unistring])])

# Currently broken on Debian :-(
# AS_VERSION_COMPARE([$LIBUNISTRING_VERSION], [0.9.1.1],
#   [AC_MSG_ERROR([GNUnet requires libunistring >= 0.9.1.1, found $LIBUNISTRING_VERSION])],
#   [AC_MSG_ERROR([GNUnet requires libunistring >= 0.9.1.1, found $LIBUNISTRING_VERSION])])

# check for sqlite
CHECK_WITH_LIB([sqlite3], [sqlite3_open], [sqlite3.h], [HAVE_SQLITE])

# check for postgres
AX_LIB_POSTGRESQL([12.0], [postgres=1], [postgres=0])
AS_IF([test "x$postgres" = "x1"],
  [SAVE_CPPFLAGS="$CPPFLAGS"
   CPPFLAGS="$POSTGRES_CPPFLAGS $CPPFLAGS"
   AC_CHECK_HEADERS([libpq-fe.h], [postgres=1], [postgres=0])])
AM_CONDITIONAL([HAVE_POSTGRESQL], [test "x$postgres" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_POSTGRESQL], [$postgres],
                   [Define to 1 if Postgres is available])

CPPFLAGS="$SAVE_CPPFLAGS"

# check for libmicrohttpd
AC_ARG_WITH([microhttpd],
  [AS_HELP_STRING([--with-microhttpd=PFX],
                  [base of libmicrohttpd installation])],
  [SAVE_PKG_PATH="$PKG_CONFIG_PATH"
   PKG_CONFIG_PATH="${withval}/lib/pkgconfig"
   export PKG_CONFIG_PATH
   PKG_CHECK_MODULES([MHD], [libmicrohttpd >= 0.9.63], [libmhd=1], [libmhd=0])
   PKG_CONFIG_PATH="$SAVE_PKG_PATH"],
  [PKG_CHECK_MODULES([MHD], [libmicrohttpd >= 0.9.63], [libmhd=1], [libmhd=0])])

AS_IF([test "x$libmhd" = "x0"],
  [AC_MSG_ERROR([GNUnet requires libmicrohttpd >= 0.9.63])])

AM_CONDITIONAL([HAVE_MHD], [test "x$libmhd" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_MHD], [$libmhd],
                   [Define to 1 if libmicrohttpd is available])
AM_CONDITIONAL([HAVE_REST], [true])

# check for gnutls
AC_ARG_WITH([gnutls],
  [AS_HELP_STRING([--with-gnutls=PFX], [base of gnutls installation])],
  [AS_CASE([$with_gnutls],
     [no],
     [gnutls=0],
     [yes],
     [AC_CHECK_HEADERS([gnutls/abstract.h],
        [AC_CHECK_LIB([gnutls], [gnutls_priority_set],
                      [gnutls=1], [gnutls=0])],
        [gnutls=0])
      AC_CHECK_HEADERS([gnutls/dane.h],
        [AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
                      [gnutls_dane=1], [gnutls_dane=0])],
        [gnutls_dane=0])],
     [LDFLAGS="-L$with_gnutls/lib $LDFLAGS"
      CPPFLAGS="-I$with_gnutls/include $CPPFLAGS"
      AC_CHECK_HEADERS([gnutls/abstract.h],
        [AC_CHECK_LIB([gnutls], [gnutls_priority_set],
                      [gnutls=1], [gnutls=0])],
        [gnutls=0])
      AC_CHECK_HEADERS([gnutls/dane.h],
        [AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
                      [gnutls_dane=1], [gnutls_dane=0])],
        [gnutls_dane=0])])],
  [AC_CHECK_HEADERS([gnutls/abstract.h],
        [AC_CHECK_LIB([gnutls], [gnutls_priority_set],
                      [gnutls=1], [gnutls=0])],
        [gnutls=0])
      AC_CHECK_HEADERS([gnutls/dane.h],
        [AC_CHECK_LIB([gnutls-dane], [dane_verify_crt_raw],
                      [gnutls_dane=1], [gnutls_dane=0])],
        [gnutls_dane=0])])
AM_CONDITIONAL([HAVE_GNUTLS], [test "x$gnutls" = "x1"])
AM_CONDITIONAL([HAVE_GNUTLS_DANE], [test "x$gnutls_dane" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_GNUTLS], [$gnutls], [Define to 1 if GnuTLS is available])
AC_DEFINE_UNQUOTED([HAVE_GNUTLS_DANE], [$gnutls_dane],
                   [Define to 1 if GnuTLS has DANE support])

# restore LIBS
LIBS=$SAVE_LIBS

# Check for standard header files.
AC_HEADER_DIRENT

# Check for headers that are ALWAYS required
# It's assumed that AC_INCLUDES_DEFAULT has been executed already, as that
# makes sure the most common headers (e.g. stdlib.h) are available
AC_CHECK_HEADERS([fcntl.h math.h errno.h ctype.h limits.h stdarg.h signal.h locale.h],
  [],
  [AC_MSG_ERROR([Compiling GNUnet requires standard UNIX header files])])

# Check for headers required only on some systems or which are optional
AC_CHECK_HEADERS([stdatomic.h malloc.h malloc/malloc.h malloc/malloc_np.h langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h sys/time.h sys/sysinfo.h sys/file.h sys/resource.h ifaddrs.h mach/mach.h sys/timeb.h argz.h ucred.h sys/ucred.h endian.h sys/endian.h execinfo.h byteswap.h])

# Required for FreeBSD's netinet/in_systm.h and netinet/ip.h
AS_IF([test "x$build_target" = "xfreebsd"],
  [AC_CHECK_HEADERS([sys/types.h netinet/in_systm.h netinet/in.h, netinet/ip.h],
     [], [],
     [#ifdef HAVE_SYS_TYPES_H
#include <sys/type.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])])

# check for gettext
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18.1])

# check for stantard typedefs, structures and compiler characteristics
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T

AC_HEADER_STAT
AC_HEADER_STDBOOL
AC_STRUCT_TM

AC_CHECK_MEMBER([struct sockaddr_in.sin_len],
  [AC_DEFINE([HAVE_SOCKADDR_IN_SIN_LEN], [1],
             [Define to 1 if struct sockaddr_in has sin_len field])],
             [], [],
             [#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>])

AC_CHECK_MEMBER([struct sockaddr_un.sun_len],
  [AC_DEFINE([HAVE_SOCKADDR_UN_SUN_LEN], [1],
             [Define to 1 if struct sockaddr_un has sun_len field])],
             [], [],
             [#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>])

AC_TYPE_OFF_T
AC_TYPE_UID_T

# check for library functions
AC_FUNC_FORK
AC_FUNC_CHOWN
AC_CHECK_FUNCS([atoll stat64 strnlen mremap getrlimit setrlimit sysconf initgroups strndup gethostbyname2 getpeerucred getpeereid setresuid getifaddrs freeifaddrs getresgid mallinfo2 malloc_size malloc_usable_size getrusage random srandom stat statfs statvfs wait4 timegm])

GN_INTLINCL=""
GN_LIBINTL="$LTLIBINTL"
GN_LIB_LDFLAGS="-export-dynamic -no-undefined"
GN_PLUGIN_LDFLAGS="-export-dynamic -avoid-version -module -no-undefined"

AC_SUBST([GN_LIB_LDFLAGS])
AC_SUBST([GN_PLUGIN_LDFLAGS])
AC_SUBST([GN_INTLINCL])
AC_SUBST([GN_LIBINTL])

AC_SUBST([CPPFLAGS])
AC_SUBST([LIBS])
AC_SUBST([LDFLAGS])
AC_SUBST([EXT_LIB_PATH])
AC_SUBST([EXT_LIBS])

AC_SUBST([LIBPREFIX])
AC_SUBST([DLLDIR])
AC_SUBST([EXT_LIB_PATH])

DATAROOTDIR=$datarootdir
AC_SUBST([DATAROOTDIR])

# check for sudo
AC_CHECK_PROGS([SUDO_BINARY], [sudo], [false])
AM_CONDITIONAL([HAVE_SUDO], [test "x$SUDO_BINARY" != "xfalse"])

# check for doas
AC_CHECK_PROGS([DOAS_BINARY], [doas], [false])
AM_CONDITIONAL([HAVE_DOAS_BINARY], [test "x$DOAS_BINARY" != "xfalse"])

# check if NSE has to send timestamp information to testbed logger for
# generating histogram of messages received
AC_ARG_ENABLE([nse-histogram],
  [AS_HELP_STRING([--enable-nse-histogram],
                  [have NSE send timestamp information to testbed logger for generating a histogram of received messages. NOT useful for production (default is no)])],
  [AS_IF([test "x$enableval" = "xno"]
         [nse_histogram=0],
         [nse_histogram=1])],
  [nse_histogram=0])
AM_CONDITIONAL([ENABLE_NSE_HISTOGRAM], [test "x$nse_histogram" = "x1"])
AC_DEFINE_UNQUOTED([ENABLE_NSE_HISTOGRAM], [$nse_histogram],
                   [Define to 1 if NSE should send timestamp information])

# check if 'make check' should run tests
AC_ARG_ENABLE([testruns],
  [AS_HELP_STRING([--disable-testruns],
                  [disable running tests on make check])],
  [enable_testruns=${enableval}],
  [enable_testruns=yes])
AM_CONDITIONAL([ENABLE_TEST_RUN], [test "x$enable_testruns" = "xyes"])

# check if benchmarks should be executed
AC_ARG_ENABLE([benchmarks],
  [AS_HELP_STRING([--enable-benchmarks],
                  [enable benchmarking (default is no)])],
  [enable_benchmarks=${enableval}],
  [enable_benchmarks=no])

AS_IF([test "x$enable_benchmarks" = "xyes"],
  [AC_DEFINE([ENABLE_BENCHMARK], [1], [Define to 1 if benchmarks are enabled])])
AM_CONDITIONAL([ENABLE_BENCHMARK], [test "x$enable_benchmarks" = "xyes"])
AM_CONDITIONAL([HAVE_BENCHMARKS], [test "x$enable_benchmarks" = "xyes"])

# check if ports should be opened for Java services
AC_ARG_ENABLE([javaports],
  [AS_HELP_STRING([--enable-javaports],
     [use non-zero ports for services with Java bindings (default is no)])],
  [enable_java_ports=${enableval}],
  [enable_java_ports="no"])

AS_IF([test "x$enable_java_ports" = "xyes"],
  [JAVAPORT=""],
  [JAVAPORT="$UNIXONLY"])
AC_SUBST([JAVAPORT])

# check if experimental code should be compiled (or at least attempted to)
AC_ARG_ENABLE([experimental],
  [AS_HELP_STRING([--enable-experimental],
                  [enable experimental code paths (default is no)])],
  [AS_IF([test "x$enableval" = "xno"],
         [enable_experimental=0],
         [enable_experimental=1])],
  [enable_experimental=0])
AM_CONDITIONAL([HAVE_EXPERIMENTAL], [test "x$enable_experimental" = "x1"])
AS_IF([test "x$enable_experimental" = "x1"],
      AC_DEFINE([GNUNET_EXPERIMENTAL], 1, [Set to 1 is this is an experimental build]))

AC_SUBST([enable_experimental])

# check if malicious code should be compiled (for testing)
AC_ARG_ENABLE([malicious],
  [AS_HELP_STRING([--enable-malicious],
    [enable malicious code path (only for testing; default is no)])],
  [AS_IF([test "x$enableval" = "xno"],
         [malicious=0],
         [malicious=1])],
  [malicious=0
   enable_malicious=no])
AM_CONDITIONAL([ENABLE_MALICIOUS], [test "x$malicious" = "x1"])
AC_DEFINE_UNQUOTED([ENABLE_MALICIOUS], [$malicious],
                   [Define to 1 if malicious code paths should be compiled])

# check if services should be started on demand when needed
# Some services may choose to never start by default
# and it is up to the service/module developer to decide
# by having "START_ON_DEMAND = NO" instead of
# "START_ON_DEMAND = @START_ON_DEMAND@"
# in the service/module's conf.in file.
# See also IMMEDIATE_START for an unconditional immediate start.
AC_ARG_ENABLE([autostart],
  [AS_HELP_STRING([--disable-autostart],
                  [do not start peer services by default])],
  [AS_IF([test "x$enableval" = "xno"],
         [START_ON_DEMAND=NO],
         [START_ON_DEMAND=YES])],
  [START_ON_DEMAND=YES])
AC_SUBST([START_ON_DEMAND])

# check if memory statistics should be kept (very expensive CPU-wise!)
AC_ARG_ENABLE([heapstats],
  [AS_HELP_STRING([--enable-heapstats], [enable expensive heap statistics])],
  [AS_IF([test "x$enableval" = "xno"],
         [enable_heapstats=0],
         [enable_heapstats=1])],
  [enable_heapstats=0])
AC_DEFINE_UNQUOTED([ENABLE_HEAP_STATISTICS], [$enable_heapstats],
                   [Define to 1 if expensive heap statistics should be enabled])

# check if the __thread storage class is available
AC_MSG_CHECKING([if __thread is supported])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <stdlib.h>
#undef __thread
static __thread int a = 1;],
[exit(a-1);])],
  [have_thread_local=1],
  [have_thread_local=0])
AC_DEFINE_UNQUOTED([HAVE_THREAD_LOCAL_GCC], [$have_thread_local],
                   [Define to 1 if __thread is supported])
AS_IF([test "x$have_thread_local" = "x1"],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])])

# check if gcov should be used
AC_ARG_ENABLE([coverage],
  [AS_HELP_STRING([--enable-coverage],
                  [compile the library with code coverage support])],
  [use_gcov=${enableval}],
  [use_gcov=no])
AM_CONDITIONAL([USE_COVERAGE], [test "x$use_gcov" = "xyes"])

# Temporarily disable a specific piece of code until TNG is out.
AC_ARG_ENABLE([transport-timing-diagnostic],
  [AS_HELP_STRING([--enable-transport-timing-diagnostic],
                  [enable logging of transport (not TNG) sending times])],
  [enable_ttd=yes],
  [enable_ttd=no])
AS_IF([test "x$enable_ttd" = "xyes"],
  [AC_DEFINE([ENABLE_TTD], [1],
             [Define if transport (not TNG) should warn about sending times.])])

# get version information
AC_PATH_PROG([gitcommand], [git])
AC_MSG_CHECKING([if source is under a VCS])
AS_IF([test "x$gitcommand" = "x"],
  [vcs_name="no"
   vcs_version="\"release\""],
  [AS_IF([test -d .git], dnl admittedly, not the best
     [git_version=$(cd $srcdir; git log -n1 --abbrev-commit | head -n1 | cut -d ' ' -f2 2>/dev/null)
      vcs_name='yes, git-svn'
      vcs_version="\"git-$git_version\""],
     [vcs_name="no"
      vcs_version="\"release\""])])
AC_MSG_RESULT([$vcs_name])
AC_DEFINE_UNQUOTED([VCS_VERSION], [$vcs_version],
                   [VCS revision/hash or tarball version])

AC_CONFIG_FILES([
Makefile
contrib/Makefile
data/Makefile
data/hellos/Makefile
scripts/Makefile
contrib/services/Makefile
contrib/services/openrc/Makefile
contrib/services/systemd/Makefile
contrib/scripts/Makefile
contrib/scripts/gnunet-logread/Makefile
doc/Makefile
doc/man/Makefile
doc/doxygen/Makefile
m4/Makefile
po/Makefile.in
src/Makefile
src/lib/Makefile
src/lib/util/Makefile
src/lib/block/Makefile
src/lib/curl/Makefile
src/lib/gnsrecord/Makefile
src/lib/json/Makefile
src/lib/pq/Makefile
src/lib/sq/Makefile
src/plugin/Makefile
src/plugin/block/Makefile
src/plugin/datacache/Makefile
src/plugin/datastore/Makefile
src/plugin/dht/Makefile
src/plugin/dns/Makefile
src/plugin/fs/Makefile
src/plugin/gns/Makefile
src/plugin/gnsrecord/Makefile
src/plugin/namecache/Makefile
src/plugin/namestore/Makefile
src/plugin/peerstore/Makefile
src/plugin/reclaim/Makefile
src/plugin/regex/Makefile
src/plugin/revocation/Makefile
src/plugin/seti/Makefile
src/plugin/setu/Makefile
src/plugin/messenger/Makefile
src/service/Makefile
src/service/arm/Makefile
src/service/arm/arm.conf
src/service/cadet/Makefile
src/service/cadet/cadet.conf
src/service/core/Makefile
src/service/core/core.conf
src/service/datacache/Makefile
src/service/datastore/Makefile
src/service/datastore/datastore.conf
src/service/dht/Makefile
src/service/dht/dht.conf
src/service/dns/Makefile
src/service/dns/dns.conf
src/service/exit/Makefile
src/service/fs/Makefile
src/service/fs/fs.conf
src/service/gns/Makefile
src/service/gns/gns.conf
src/service/gns/nss/Makefile
src/service/hostlist/Makefile
src/service/identity/Makefile
src/service/identity/identity.conf
src/service/messenger/Makefile
src/service/messenger/messenger.conf
src/service/namecache/Makefile
src/service/namecache/namecache.conf
src/service/namestore/Makefile
src/service/namestore/namestore.conf
src/service/nat/Makefile
src/service/nat/nat.conf
src/service/nat-auto/Makefile
src/service/nat-auto/nat-auto.conf
src/service/nse/Makefile
src/service/nse/nse.conf
src/service/peerstore/Makefile
src/service/peerstore/peerstore.conf
src/service/pt/Makefile
src/service/reclaim/Makefile
src/service/regex/Makefile
src/service/regex/regex.conf
src/service/rest/Makefile
src/service/revocation/Makefile
src/service/revocation/revocation.conf
src/service/seti/Makefile
src/service/seti/seti.conf
src/service/setu/Makefile
src/service/setu/setu.conf
src/service/statistics/Makefile
src/service/statistics/statistics.conf
src/service/testing/Makefile
src/service/topology/Makefile
src/service/transport/Makefile
src/service/transport/transport.conf
src/service/util/Makefile
src/service/util/resolver.conf
src/service/vpn/Makefile
src/service/vpn/vpn.conf
src/service/zonemaster/Makefile
src/service/zonemaster/zonemaster.conf
src/cli/Makefile
src/cli/arm/Makefile
src/cli/cadet/Makefile
src/cli/core/Makefile
src/cli/datastore/Makefile
src/cli/dht/Makefile
src/cli/fs/Makefile
src/cli/gns/Makefile
src/cli/identity/Makefile
src/cli/messenger/Makefile
src/cli/namecache/Makefile
src/cli/namestore/Makefile
src/cli/peerstore/Makefile
src/cli/nat/Makefile
src/cli/nat-auto/Makefile
src/cli/nse/Makefile
src/cli/reclaim/Makefile
src/cli/revocation/Makefile
src/cli/statistics/Makefile
src/cli/util/Makefile
src/cli/vpn/Makefile
src/contrib/Makefile
src/contrib/service/Makefile
src/contrib/service/abd/Makefile
src/contrib/service/abd/abd.conf
src/contrib/service/auction/Makefile
src/contrib/service/consensus/Makefile
src/contrib/service/consensus/consensus.conf
src/contrib/service/conversation/Makefile
src/contrib/service/conversation/conversation.conf
src/contrib/service/scalarproduct/Makefile
src/contrib/service/scalarproduct/scalarproduct.conf
src/contrib/service/secretsharing/Makefile
src/contrib/service/secretsharing/secretsharing.conf
src/contrib/service/set/Makefile
src/contrib/service/set/set.conf
src/contrib/service/rps/Makefile
src/contrib/service/rps/rps.conf
src/contrib/service/template/Makefile
src/contrib/cli/Makefile
src/contrib/cli/template/Makefile
src/lib/hello/Makefile
src/include/Makefile
src/include/gnunet_config.h
pkgconfig/Makefile
pkgconfig/gnunetarm.pc
pkgconfig/gnunetblock.pc
pkgconfig/gnunetcadet.pc
pkgconfig/gnunetconsensus.pc
pkgconfig/gnunetconversation.pc
pkgconfig/gnunetcore.pc
pkgconfig/gnunetdatacache.pc
pkgconfig/gnunetdatastore.pc
pkgconfig/gnunetdht.pc
pkgconfig/gnunetdns.pc
pkgconfig/gnunetfs.pc
pkgconfig/gnunetgns.pc
pkgconfig/gnunethello.pc
pkgconfig/gnunetidentity.pc
pkgconfig/gnunetjson.pc
pkgconfig/gnunetmessenger.pc
pkgconfig/gnunetmicrophone.pc
pkgconfig/gnunetnamestore.pc
pkgconfig/gnunetnat.pc
pkgconfig/gnunetnse.pc
pkgconfig/gnunetpq.pc
pkgconfig/gnunetreclaim.pc
pkgconfig/gnunetregex.pc
pkgconfig/gnunetrevocation.pc
pkgconfig/gnunetrps.pc
pkgconfig/gnunetscalarproduct.pc
pkgconfig/gnunetset.pc
pkgconfig/gnunetspeaker.pc
pkgconfig/gnunetstatistics.pc
pkgconfig/gnunettesting.pc
pkgconfig/gnunettransport.pc
pkgconfig/gnunetutil.pc
pkgconfig/gnunetvpn.pc
])

AC_OUTPUT

# notice about Java ports
AS_IF([test "x$enable_java_ports" = "xyes"],
  [AC_MSG_NOTICE([Opening TCP ports to enable gnunet-java bindings])
   java_msg="yes"],
  [java_msg="no"])

# experimental code is enabled
AS_IF([test "x$enable_experimental" = "x1"],
  [experimental_msg="yes"],
  [experimental_msg="no"])

# experimental code for transport is enabled
transport_msg="tcp udp unix http"
AS_IF([test "x$build_target" = "xlinux" && test "x$enable_experimental" = "x1"],
  [transport_msg="tcp udp unix http wlan"])

# libidn version
AS_IF([test "x$libidn_version" = "x2"],
  [libidn_msg="libidn2"],
  [libidn_msg="libidn"])

# mandoc
AS_IF([test "x$MANDOC_BINARY" = "xfalse"],
  [mandoc_msg="no"],
  [mandoc_msg="yes"])

# doxy
AS_IF([$DOXY_BINARY],
  [doxy_msg="yes"],
  [doxy_msg="no"])

# conversation
conversation_msg="no"
AS_IF([test "x$pulse" = "x1"],
  [libpulse_msg="yes"],
  [libpulse_msg="no"])
AS_IF([test "x$opus" = "x1"],
  [libopus_msg="yes"],
  [libopus_msg="no"])
gstreamer_msg="no"
AS_IF([test "x$conversation_backend" = "xnone"],
  [AS_IF([test "x$pulse" != "x1"],
     [libpulse_msg="no (required to build conversation)"],
     [libpulse_msg="yes"])
   AS_IF([test "x$opus" != "x1"],
     [libopus_msg="no (required to build conversation)"],
     [libopus_msg="yes"])
   AS_IF([test "x$gst" != "x1"],
     [gstreamer_msg="no (required to build conversation)"],
     [gstreamer_msg="yes"])],
  [AS_IF([test "x$opus" = "x1"],
     [conversation_msg="yes ($conversation_backend)"],
     [conversation_msg="no"])])

# default network interface
interface_msg=$(echo "$DEFAULT_INTERFACE" | tr -d \")

# libextractor
AS_IF([test "x$extractor" = "x0"],
  [libextractor_msg="no"
   AC_MSG_WARN([libextractor not found, but various file-sharing operations require it])],
  [libextractor_msg="yes"])

AC_SUBST([extractor])

# libzbar
AS_IF([test "x$zbar" = "x1"],
  [libzbar_msg="yes"],
  [libzbar_msg="no"])

# libpng
AS_IF([test "x$png" = "x1"],
  [libpng_msg="yes"],
  [libpng_msg="no"])

AS_IF([test "x$curl_gnutls" = "x0"],
       [curl_tls_backend="OpenSSL"],
       [curl_tls_backend="GnuTLS"])

# ifconfig
AS_IF([test "x$IFCONFIG_BINARY" = "xfalse"],
  [ifconfig_msg="no (some features might not work)"],
  [ifconfig_msg="yes"])

# upnpc
AS_IF([test "x$UPNPC_BINARY" = "xfalse"],
  [upnpc_msg="no (NAT traversal might not work)"],
  [upnpc_msg="yes"])

# iptables
AS_IF([test "x$IPTABLES_BINARY" = "xfalse"],
  [iptables_msg="no (DNS query interception might not work)"],
  [iptables_msg="yes"])

# bluetooth
AS_IF([test "x$bluetooth" = "x0"],
  [bluetooth_msg="no"],
  [bluetooth_msg="yes"])

# gnutls
AS_IF([test "x$gnutls" = "x0"],
  [gnutls_msg="no"],
  [AS_IF([test "x$gnutls_dane" = "x0"],
     [gnutls_msg="yes (without DANE support)"
      AC_MSG_WARN([GnuTLS lacks DANE support; validation using it will not be possible])],
     [gnutls_msg="yes (with DANE support)"])])

# pdflatex
AS_IF([test "x$PDFLATEX_BINARY" = "xfalse"],
  [latex_msg="no"],
  [latex_msg="yes"])

# database backends
features_msg=""

AS_IF([test "x$sqlite3" = "x1"],
  [sqlite_msg="yes"
   features_msg="sqlite $features_msg"],
  [sqlite_msg="no"])

AS_IF([test "x$postgres" = "x1"],
  [postgres_msg="yes"
   features_msg="postgres $features_msg"],
  [postgres_msg="no"])

# Too new versions of Python might cause compatibility issues, so output a
# warning when the version found goes above the recommended maximum version.
AS_VERSION_COMPARE([$PYTHON_VERSION],[3.8],[],[],
  [AC_MSG_WARN([Your version of Python is not supported, you might see issues])])

AC_MSG_NOTICE([
Detected system
===============

GNUnet version:                 ${VERSION}

Host Setup:                     ${host}
Install Prefix:                 ${prefix}
Compiler:                       ${CC}
CFLAGS:                         ${CFLAGS}
CPPFLAGS:                       ${CPPFLAGS}
LDFLAGS:                        ${LDFLAGS}
LIBS:                           ${LIBS}
Build Target:                   ${build_target}

Default Interface:              ${interface_msg}

sqlite3:                        ${sqlite_msg}
PostgreSQL:                     ${postgres_msg}

cURL TLS backend:               ${curl_tls_backend}
Bluetooth:                      ${bluetooth_msg}
iptables:                       ${iptables_msg}
ifconfig:                       ${ifconfig_msg}
UPnPc:                          ${upnpc_msg}
GnuTLS:                         ${gnutls_msg}

LaTeX:                          ${latex_msg}

libextractor:                   ${libextractor_msg}
libzbar:                        ${libzbar_msg}
libpng:                         ${libpng_msg}
libidn:                         ${libidn_msg}
libopus:                        ${libopus_msg}
libpulse:                       ${libpulse_msg}
gstreamer:                      ${gstreamer_msg}

Java:                           ${java_msg}

doxygen:                        ${doxy_msg}
mandoc:                         ${mandoc_msg}

GNUnet configuration
====================

Transports:                     ${transport_msg}
Conversation:                   ${conversation_msg}
Database Backends               ${features_msg}
Experimental Code:              ${experimental_msg}

Transpiled mdocml Manual:       ${mdocml_msg}
])

AS_IF([test "x$MSG_USER_SETUP" != "xfalse"],
  [AC_MSG_WARN([Please make sure NOW to create a user and group 'gnunet' and additionally a group 'gnunetdns'. Make sure that '/var/lib/gnunet' is owned (and writable) by user 'gnunet'.])
   AS_IF([test "x$HAVE_GNUNET_USER" != "x0"],
     [AC_MSG_NOTICE([To do this on this system, run:
# addgroup gnunetdns
# adduser --system --disabled-login --home /var/lib/gnunet gnunet
])])
   AC_MSG_WARN([Each user of GNUnet should be added to the 'gnunet' group])
   AS_IF([test "x$HAVE_GNUNET_USER" != "x0"],
     [AC_MSG_NOTICE([To do this on this system, run:
# adduser USERNAME gnunet
for each of your users, replacing 'USERNAME' with the respective login name.
Users may have to login again for the changes to take effect.])])])

AC_MSG_NOTICE([For detailed setup instructions, type 'info gnunet' after the installation or visit https://docs.gnunet.org/])
