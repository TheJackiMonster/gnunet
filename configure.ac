# This file is part of GNUnet.
# (C) 2001--2021 GNUnet e.V.
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
AC_INIT([gnunet], m4_esyscmd_s([contrib/get_version.sh]), [bug-gnunet@gnu.org])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])

AC_CONFIG_HEADERS([gnunet_config.h])

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
   xbsd="yes"
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*openbsd*],
  [# libc needs to be linked explicitly
   LDFLAGS="$LDFLAGS -Wl -lc"
   # and PIC has to be enabled
   CFLAGS="-fPIC $CFLAGS"
   build_target="openbsd"
   xbsd="yes"
   LIBPREFIX=
   DLLDIR=lib
   UNIXONLY="#"
  ],
  [*netbsd*],
  [build_target="netbsd"
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
AC_CHECK_PROGS([UNCRUSTIFY_BINARY], [uncrustify], [true])
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
AM_CONDITIONAL([DOCUMENTATION], [test "x$documentation" = "xyes"])
AS_IF([test "x$documentation" = "xyes"],
      [AC_DEFINE([DOCUMENTATION], [1], [Define to 1 if documentation is built])],
      [AC_DEFINE([DOCUMENTATION], [0], [Define to 1 if documentation is built])])

AC_ARG_ENABLE([texi2mdoc-generation],
              [AS_HELP_STRING([--enable-texi2mdoc-generation],
                              [generate and install texi2mdoc output])],
              [texi2mdoc_enabled=${enableval}],
              [texi2mdoc_enabled=no])
AM_CONDITIONAL([TEXI2MDOC_GENERATION], [test "x$texi2mdoc_enabled" = "xyes"])
AS_IF([test "x$texi2mdoc_enabled" = "xyes"],
  [AC_CHECK_PROGS([TEXI2MDOC_BINARY], [texi2mdoc], [false])
   AS_IF([test "x$TEXI2MDOC_BINARY" != "xfalse"],
     [AC_DEFINE([TEXI2MDOC_GENERATION], [1],
                [Define to 1 if mdoc output is generated])],
     [AC_DEFINE([TEXI2MDOC_GENERATION], [0],
               [Define to 1 if mdoc output is generated])])],
  [TEXI2MDOC_BINARY=false])
AM_CONDITIONAL([HAVE_TEXI2MDOC], [test "x$TEXI2MDOC_BINARY" != "xfalse"])

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

# Do we have texinfo4? If yes, it is used to set texinfo4 specific switches
# (not syntax!) to the commandline tools which generate the html. If not,
# texinfo5 switches are used. This comes with no version checks, is
# enabled only at distributors action (ie defaults to "no").
# Mantis #3914 for more details (https://bugs.gnunet.org/view.php?id=3914)
# While GNU makeinfo 6.5 supports --css-ref=URL,
# makeinfo 4.8 (in NetBSD 8.0, macOS, and maybe other
# base) does only support --css-include=FILE.
# The only difference is a shorter html output and
# in 6.5 the ability to use refs instead of include.
# We prefer not to break builds in this case, so
# we use the include version which is backwards compatible
# and upwards compatible, while the ref variant is neither.
# In the 5.x version they added `--split=chapters|sections` in
# addition to `--split=nodes`.
# Hold on to your hats: In version 6.5 this is already removed, ffs.
# GNU Texinfo, please be more consistent than 1 version in switches.
AC_ARG_ENABLE([texinfo4],
              [AS_HELP_STRING([--enable-texinfo4],
                              [Use Texinfo version 4 specific switches])],
              [activate_texinfo4=${enableval}],
              [activate_texinfo4=no])
AM_CONDITIONAL([ACTIVATE_TEXINFO4], [test "x$activate_texinfo4" = "xyes"])
AS_IF([test "x$activate_texinfo4" = "xyes"],
      [AC_DEFINE([ACTIVATE_TEXINFO4], [1],
                 [Define to 1 if using Texinfo v4 switches])
       TEXINFO_HTMLFLAGS="--no-split --css-include=style.css --css-include=manual.css"],
      [AC_DEFINE([ACTIVATE_TEXINFO4], [0],
                 [Define to 1 if using Texinfo v4 switches])
       TEXINFO_HTMLFLAGS="--no-split --css-ref='../style.css' --css-ref='../manual.css'"])
AC_SUBST([TEXINFO_HTMLFLAGS])

# Hardening options
AC_ARG_ENABLE([gcc-hardening],
  [AS_HELP_STRING([--enable-gcc-hardening], [enable compiler security checks])],
  [AS_IF([test "x$enableval" = "xyes"],
     [CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-all"
      CFLAGS="$CFLAGS -fwrapv -fPIE -Wstacl-protector"
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
           [extra_loging=GNUNET_YES],
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

AC_MSG_CHECKING([for static assertion support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
                     [[_Static_assert(sizeof(int) >= 4, "not big enough");]])],
                  [AC_MSG_RESULT([yes])
                   AC_DEFINE([HAVE_STATIC_ASSERT], [1],
                             [Define to 1 if static assert is supported])],
                  [AC_MSG_RESULT([no])
                   AC_DEFINE([HAVE_STATIC_ASSERT], [0],
                             [Define to 1 if static assert is supported])])

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

# check for libpulse (pulseaudio)
CHECK_WITH_LIB([pulse], [pa_stream_peek], [pulse/simple.h], [HAVE_PULSE])

# check for libopus
# Note: this might need to be expanded if a more detailed check is needed.
# For example, before CHECK_WITH_LIB was created, it used to look for
# "OPUS_SET_GAIN" in libopus
CHECK_WITH_LIB([opus], [opus_decode_float], [opus/opus.h], [HAVE_OPUS])

# check for libogg
CHECK_WITH_LIB([ogg], [ogg_stream_flush_fill], [ogg/ogg.h], [HAVE_OGG])

PKG_CHECK_MODULES([GLIB], [glib-2.0],
  [AC_CHECK_HEADER([pbc/pbc.h], [pbc=1], [pbc=0])
   AC_CHECK_HEADER([gabe.h], [abe=1], [abe=0])
   AM_CONDITIONAL([HAVE_PBC], [test "x$pbc" = "x1"])
   AM_CONDITIONAL([HAVE_ABE], [test "x$abe" = "x1"])
   AC_DEFINE_UNQUOTED([HAVE_PBC], [$pbc], [Define to 1 if pbc is available])
   AC_DEFINE_UNQUOTED([HAVE_ABE], [$abe], [Define to 1 if abe is available])],
  [AM_CONDITIONAL([HAVE_PBC], [false])
   AM_CONDITIONAL([HAVE_ABE], [false])
   AC_DEFINE([HAVE_PBC], [0], [Define to 1 if pbc is available])
   AC_DEFINE([HAVE_ABE], [0], [Define to 1 if abe is available])])

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

# check for libgnurl
LIBGNURL_CHECK_CONFIG([], [7.34.0],
                      [gnurl=1
                       curl=0],
                      [gnurl=0
                       curl=0])
AS_IF([test "x$gnurl" = "x0"],
  [LIBCURL_CHECK_CONFIG([], [7.34.0], [curl=1], [curl=0])
   AS_IF([test "x$curl" = "x0"],
     [AC_CHECK_HEADER([curl/curl.h],
        [AC_CHECK_DECLS([CURLINFO_TLS_SESSION],
                        [curl=1],
                        [curl=0],
                        [[#include <curl/curl.h>]])])
      AC_CHECK_LIB([curl-gnutls],
                   [curl_easy_getinfo],
                   [curl_gnutls=1],
                   [curl_gnutls=0])])
   AS_IF([test "x$curl" = "x0" || test "x$curl_gnutls" = "x0"],
     [AC_MSG_ERROR([cURL must have a version >= 7.34.0 and must support CURLINFO_TLS_SESSION])])])

AS_IF([test "x$gnurl" = "x0" && test "x$curl" = "x0"],
  [AC_MSG_ERROR([either gnurl or cURL must be available])])

AM_CONDITIONAL([HAVE_LIBGNURL], [test "x$gnurl" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_LIBGNURL], [$gnurl], [Define to 1 if libgnurl is used])
AM_CONDITIONAL([HAVE_LIBCURL], [test "x$curl" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_LIBCURL], [$curl], [Define to 0 if libcurl is used])

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
AC_CHECK_HEADER([sodium.h],
  [AC_CHECK_LIB([sodium], [crypto_core_ed25519_scalar_mul],
                [libsodium=1],
                [libsodium=0])])

AS_IF([test "x$libsodium" = "x0"],
      [AC_MSG_ERROR([GNUnet requires libsodium >= 1.0.18])])

# check for libextractor
CHECK_WITH_LIB([extractor],
               [EXTRACTOR_plugin_add_defaults],
               [extractor.h],
               [HAVE_LIBEXTRACTOR])
AS_IF([test "x$extractor" = "x0"],
      [AC_MSG_ERROR([GNUnet requires libextractor])])

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
gl_LIBUNISTRING
AS_IF([test "x$HAVE_LIBUNISTRING" != "xyes"],
      [AC_MSG_ERROR([GNUnet requires libunistring])])

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

# check for mysql
SAVE_LDFLAGS="$LDFLAGS"
SAVE_CPPFLAGS="$CPPFLAGS"
AC_ARG_WITH([mysql],
  [AS_HELP_STRING([--with-mysql=PFX], [base of mysql installation])],
  [AS_CASE([$withval],
     [no],
     [],
     [yes|""],
     [AC_CHECK_HEADERS([mysql/mysql.h],
        [AC_CHECK_LIB([mysqlclient], [mysql_init],
                      [mysql=true], [mysql=false])])],
     [LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql $LDFLAGS $ZLIBS"
      CPPFLAGS="-I$with_mysql/include $CPPFLAGS"
      AC_CHECK_HEADERS([mysql/mysql.h],
        [AC_CHECK_LIB([mysqlclient], [mysql_init],
                      [MYSQL_LDFLAGS="-L$with_mysql/lib -L$with_mysql/lib/mysql"
                       MYSQL_CPPFLAGS="-I$with_mysql/include"
                       mysql=true],
                      [mysql=false])])])],
   [AS_IF([test -d "/usr/lib64/mysql"],
      [MYSQL_LIBDIR="/usr/lib64/mysql"],
      [AS_IF([test -d "/usr/lib/mysql"],
         [MYSQL_LIBDIR="/usr/lib/mysql"],
         [MYSQL_LIBDIR="/usr/lib"])])
    LDFLAGS="-L$MYSQL_LIBDIR $LDFLAGS $ZLIBS"
    AC_CHECK_LIB([mysqlclient], [mysql_init],
      [AC_CHECK_HEADERS([mysql/mysql.h],
         [MYSQL_LDFLAGS="-L$MYSQL_LIBDIR"
          mysql=true],
         [mysql=false])],
      [mysql=false])])
AC_SUBST(MYSQL_LDFLAGS)
AC_SUBST(MYSQL_CPPFLAGS)

# additional version checks for mysql
AS_IF([test "x$mysql" = "xtrue"],
  [AC_MSG_CHECKING([for mysql version])
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
     [[include <mysql/mysql_version.h>]],
     [[#if (MYSQL_VERSION_ID < 40100)
#error required at least version 4.1
#endif]])],
     [mysql=true],
     [mysql=false])
   AS_IF([test "x$mysql" = "xfalse"],
     [AC_MSG_RESULT([< 4.1])
      AC_MSG_ERROR([mysql version >= 4.1 required])])
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
     [[#include <mysql/mysql_version.h>]],
     [[#if (MYSQL_VERSION_ID < 80000)
#error needs at least version 8.0
#endif]])],
     [mysql8=true],
     [mysql8=false])])

AS_IF([test "x$mysql" = "xtrue"],
  [AS_IF([test "x$mysql8" = "xfalse"],
     [AC_MSG_RESULT([between 4.1 and 8.0])],
     [AC_MSG_RESULT([> 8.0])
      AC_DEFINE([HAVE_MYSQL8], [1],
                [Define to 1 if MySQL is at least version 8])])])

AM_CONDITIONAL([HAVE_MYSQL], [test "x$mysql" = "xtrue"])
AM_CONDITIONAL([HAVE_MYSQLE], [false])

AS_IF([test "x$sqlite3" = "x0" && test "x$mysql" = "xfalse" && test "x$postgres" = "x0"],
  [AC_MSG_ERROR([GNUnet requires either SQLite, MySQL/MariaDB or PostgreSQL])])

LDFLAGS="$SAVE_LDFLAGS"
CPPFLAGS="$SAVE_CPPFLAGS"

# check for libmicrohttpd
AC_ARG_WITH([microhttpd],
  [AS_HELP_STRING([--with-microhttpd=PFX],
                  [base of libmicrohttpd installation])],
  [httpd=${withval}],
  [httpd=check])

AS_CASE([$withval],
  [no],
  [AC_MSG_ERROR([GNUnet requires libmicrohttpd >= 0.9.63])],
  [yes],
  [PKG_CHECK_MODULES([MHD], [libmicrohttpd >= 0.9.63], [libmhd=1], [libmhd=0])],
  [SAVE_PKG_PATH="$PKG_CONFIG_PATH"
   PKG_CONFIG_PATH="$httpd/lib/pkgconfig"
   export PKG_CONFIG_PATH
   PKG_CHECK_MODULES([MHD], [libmicrohttpd >= 0.9.63], [libmhd=1], [libmhd=0])
   PKG_CONFIG_PATH="$SAVE_PKG_PATH"])

AS_IF([test "x$libmhd" = "x0"],
  [AC_MSG_ERROR([GNUnet requires libmicrohttpd >= 0.9.63])])

AM_CONDITIONAL([HAVE_MHD], [test "x$libmhd" = "x1"])
AC_DEFINE_UNQUOTED([HAVE_MHD], [$libmhd],
                   [Define to 1 if libmicrohttpd is avaliable])
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
AC_CHECK_HEADERS([stdatomic.h malloc.h malloc/malloc.h malloc/malloc_np.h
                  langinfo.h sys/param.h sys/mount.h sys/statvfs.h sys/select.h
                  sockLib.h sys/mman.h sys/msg.h sys/vfs.h arpa/inet.h
                  libintl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h
                  sys/time.h sys/sysinfo.h sys/file.h sys/resource.h
                  ifaddrs.h mach/mach.h sys/timeb.h argz.h ucred.h
                  sys/ucred.h endian.h sys/endian.h execinfo.h byteswap.h])

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
AC_CHECK_FUNCS([atoll stat64 strnlen mremap getrlimit setrlimit sysconf
                initgroups strndup gethostbyname2 getpeerucred getpeereid
                setresuid getifaddrs freeifaddrs getresgid mallinfo malloc_size
                malloc_usable_size getrusage random srandom stat statfs statvfs
                wait4 timegm])

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
                   [Define to 1 if NSE should send timestamp informations])

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
  [enable_experimental="${enableval}"]
  [enable_experimental="no"])
AM_CONDITIONAL([HAVE_EXPERIMENTAL], [test "x$enable_experimental" = "xyes"])

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

# get version informations
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
bin/Makefile
contrib/Makefile
contrib/hellos/Makefile
contrib/services/Makefile
contrib/services/openrc/Makefile
contrib/services/systemd/Makefile
contrib/scripts/Makefile
contrib/scripts/gnunet-logread/Makefile
doc/Makefile
doc/man/Makefile
doc/doxygen/Makefile
doc/handbook/Makefile
doc/tutorial/Makefile
m4/Makefile
po/Makefile.in
src/Makefile
src/arm/Makefile
src/arm/arm.conf
src/ats/Makefile
src/ats/ats.conf
src/ats-tool/Makefile
src/auction/Makefile
src/block/Makefile
src/cadet/Makefile
src/cadet/cadet.conf
src/core/Makefile
src/core/core.conf
src/consensus/Makefile
src/consensus/consensus.conf
src/conversation/Makefile
src/conversation/conversation.conf
src/curl/Makefile
src/datacache/Makefile
src/datastore/Makefile
src/datastore/datastore.conf
src/dht/Makefile
src/dht/dht.conf
src/dhtu/Makefile
src/dns/Makefile
src/dns/dns.conf
src/exit/Makefile
src/fragmentation/Makefile
src/fs/Makefile
src/fs/fs.conf
src/gns/Makefile
src/gns/gns.conf
src/gns/nss/Makefile
src/gnsrecord/Makefile
src/hello/Makefile
src/identity/Makefile
src/identity/identity.conf
src/include/Makefile
src/integration-tests/Makefile
src/json/Makefile
src/hostlist/Makefile
src/my/Makefile
src/mysql/Makefile
src/namecache/Makefile
src/namecache/namecache.conf
src/namestore/Makefile
src/namestore/namestore.conf
src/nat/Makefile
src/nat/nat.conf
src/nat-auto/Makefile
src/nat-auto/nat-auto.conf
src/nse/Makefile
src/nse/nse.conf
src/nt/Makefile
src/peerinfo/Makefile
src/peerinfo/peerinfo.conf
src/peerinfo-tool/Makefile
src/peerstore/Makefile
src/peerstore/peerstore.conf
src/pq/Makefile
src/pt/Makefile
src/regex/Makefile
src/regex/regex.conf
src/revocation/Makefile
src/revocation/revocation.conf
src/rps/Makefile
src/rps/rps.conf
src/secretsharing/Makefile
src/secretsharing/secretsharing.conf
src/scalarproduct/Makefile
src/scalarproduct/scalarproduct.conf
src/set/Makefile
src/set/set.conf
src/seti/Makefile
src/seti/seti.conf
src/setu/Makefile
src/setu/setu.conf
src/sq/Makefile
src/statistics/Makefile
src/statistics/statistics.conf
src/template/Makefile
src/testbed/Makefile
src/testbed/testbed.conf
src/testbed-logger/Makefile
src/testbed-logger/testbed-logger.conf
src/testing/Makefile
src/topology/Makefile
src/transport/Makefile
src/transport/transport.conf
src/util/Makefile
src/util/resolver.conf
src/vpn/Makefile
src/vpn/vpn.conf
src/zonemaster/Makefile
src/zonemaster/zonemaster.conf
src/rest/Makefile
src/abe/Makefile
src/reclaim/Makefile
src/messenger/Makefile
src/messenger/messenger.conf
pkgconfig/Makefile
pkgconfig/gnunetarm.pc
pkgconfig/gnunetats.pc
pkgconfig/gnunetblock.pc
pkgconfig/gnunetcadet.pc
pkgconfig/gnunetconsensus.pc
pkgconfig/gnunetconversation.pc
pkgconfig/gnunetcore.pc
pkgconfig/gnunetdatacache.pc
pkgconfig/gnunetdatastore.pc
pkgconfig/gnunetdht.pc
pkgconfig/gnunetdns.pc
pkgconfig/gnunetenv.pc
pkgconfig/gnunetfragmentation.pc
pkgconfig/gnunetfs.pc
pkgconfig/gnunetgns.pc
pkgconfig/gnunethello.pc
pkgconfig/gnunetidentity.pc
pkgconfig/gnunetmicrophone.pc
pkgconfig/gnunetmysql.pc
pkgconfig/gnunetnamestore.pc
pkgconfig/gnunetnat.pc
pkgconfig/gnunetnse.pc
pkgconfig/gnunetpeerinfo.pc
pkgconfig/gnunetpq.pc
pkgconfig/gnunetregex.pc
pkgconfig/gnunetrevocation.pc
pkgconfig/gnunetrps.pc
pkgconfig/gnunetscalarproduct.pc
pkgconfig/gnunetset.pc
pkgconfig/gnunetspeaker.pc
pkgconfig/gnunetstatistics.pc
pkgconfig/gnunettestbed.pc
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
AS_IF([test "x$enable_experimental" = "xyes"],
  [experimental_msg="yes"],
  [experimental_msg="no"])

# experimental code for transport is enabled
transport_msg="tcp udp unix http"
AS_IF([test "x$build_target" = "xlinux" && test "x$enable_experimental" = "xyes"],
  [transport_msg="tcp udp unix http wlan"])

# libidn version
AS_IF([test "x$libidn_version" = "x2"],
  [libidn_msg="libidn2"],
  [libidn_msg="libidn"])

# texi2mdoc
AS_IF([test "x$texi2mdoc_enabled" = "xyes"],
  [mdocml_msg="yes"],
  [mdocml_msg="no"])
AS_IF([test "x$TEXI2MDOC_BINARY" = "xfalse"],
  [mdocbin_msg="no"],
  [mdocbin_msg="yes"])

# mandoc
AS_IF([test "x$MANDOC_BINARY" = "xfalse"],
  [mandoc_msg="no"],
  [mandoc_msg="yes"])

# texinfo
AS_IF([test "x$documentation" = "xyes"],
  [texinfo_msg="yes"],
  [texinfo_msg="no"])

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

# libzbar
AS_IF([test "x$zbar" = "x1"],
  [libzbar_msg="yes"],
  [libzbar_msg="no"])

# libpng
AS_IF([test "x$png" = "x1"],
  [libpng_msg="yes"],
  [libpng_msg="no"])

# curl or gnurl
AS_IF([test "x$gnurl" = "x1"],
  [http_client="gnurl"],
  [AS_IF([test "x$curl_gnutls" = "x1"],
     [http_client="curl-gnutls"],
     [http_client="curl-openssl"])])

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

# database backends
features_msg=""

AS_IF([test "x$sqlite3" = "x1"],
  [sqlite_msg="yes"
   features_msg="sqlite $features_msg"],
  [sqlite_msg="no"])

AS_IF([test "x$mysql" = "xtrue"],
  [mysql_msg="yes"
   features_msg="mysql $features_msg"],
  [mysql_msg="no"])

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
MySQL:                          ${mysql_msg}
PostgreSQL:                     ${postgres_msg}

HTTP Client:                    ${http_client}
Bluetooth:                      ${bluetooth_msg}
iptables:                       ${iptables_msg}
ifconfig:                       ${ifconfig_msg}
UPnPc:                          ${upnpc_msg}
GnuTLS:                         ${gnutls_msg}

libextractor:                   ${libextractor_msg}
libzbar:                        ${libzbar_msg}
libpng:                         ${libpng_msg}
libidn:                         ${libidn_msg}
libopus:                        ${libopus_msg}
libpulse:                       ${libpulse_msg}
gstreamer:                      ${gstreamer_msg}

Java:                           ${java_msg}

texi2mdoc:                      ${mdocbin_msg}
mandoc:                         ${mandoc_msg}

GNUnet configuration
====================

Transports:                     ${transport_msg}
Conversation:                   ${conversation_msg}
Database Backends               ${features_msg}
Experimental Code:              ${experimental_msg}

Texinfo Manual:                 ${texinfo_msg}
Transpiled mdocml Manual:       ${mdocml_msg}
])

AS_IF([test "x$MSG_USER_SETUP" != "xfalse"],
  [AC_MSG_WARN([Please make sure NOW to create a user and group 'gnunet' and additionall a group 'gnunetdns'. Make sure that '/var/lib/gnunet' is owned (and writable) by user 'gnunet'.])
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
