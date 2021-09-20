# Autoconf macro for working with GNUnet
# This file is in the public domain.
#
# AM_PATH_GNUNET([MINIMUM-VERSION = 0.15.3, [ACTION-IF-FOUND, [ACTION-IF-NOT-FOUND]]])
# Find the GNUnet installation, either automatically or through the
# --with-gnunet-prefix flag
#
# This macro runs the pkg-config and, if needed, the gnunet-config tool
# provided by GNUnet itself.
#
# The gnunet-config tool can be overridden by setting the GNUNET_CONFIG
# variable before executing the configure script.
#
# The variables GNUNET_CFLAGS and GNUNET_LIBS will be set to appropriate
# values and are made available to Automake.
AC_DEFUN([AM_PATH_GNUNET],
[AC_ARG_WITH([gnunet-prefix],
             [AS_HELP_STRING([--with-gnunet-prefix=PATH],
                             [PATH to the GNUnet installation])],
             [gnunet_prefix="$withval"],
             [gnunet_prefix=""])
 AC_ARG_ENABLE([debug-log],
               [AS_HELP_STRING([--disable-debug-log],
                               [Disable all DEBUG-level logging])],
               [],
               [enable_debug_log=yes])
 AC_ARG_VAR([GNUNET_CONFIG],[The gnunet-config tool])
 min_gnunet_version=m4_if([$1], ,0.15.3,$1)
 # Make sure the specified version is at least the version with
 # the features required to use this macro
 AS_VERSION_COMPARE([$min_gnunet_version],[0.15.3],
                    [AC_MSG_WARN([The specified GNUnet version $min_gnunet_version is too old.])
                     AC_MSG_WARN([The minimum version has been set to 0.15.3])
                     min_gnunet_version="0.15.3"])
 AS_IF([test "x${GNUNET_CONFIG+set}" != "xset"],
       [PKG_CHECK_MODULES([GNUNET],[gnunetutil >= $min_gnunet_version],
                          [gnunet_pkgconfig=yes],[gnunet_pkgconfig=no])
        AS_IF([test "x$gnunet_pkgconfig" = "xno" && test "x$gnunet_prefix" != "x"],
              [gnunet_PATH="$PATH"
               AS_IF([test "x$prefix" != "xNONE"],
                     [gnunet_PATH="$prefix/bin${PATH_SEPARATOR}$prefix/usr/bin"])
               AC_PATH_PROG([GNUNET_CONFIG],[gnunet-config],[no],[$gnunet_PATH])
               AS_UNSET([gnunet_PATH])],
              [GNUNET_CONFIG="pkg-config gnunetutil"])])
 AC_MSG_CHECKING([if GNUnet version is >= $min_gnunet_version])
 gnunet_result=no
 AS_IF([test "x$GNUNET_CONFIG" != "xno" && test -n "$GNUNET_CONFIG"],
       [gnunet_version=`$GNUNET_CONFIG --version | tr ' ' '\n' | sed -n '2p'`
        AS_VERSION_COMPARE([$gnunet_version],[$min_gnunet_version],
                           [gnunet_result=no],
                           [gnunet_result=yes],
                           [gnunet_result=yes])
        AS_UNSET([gnunet_version])])
 AS_IF([test "x$gnunet_result" != "xyes"],
       [AC_MSG_RESULT([no])
        m4_if([$3], ,:,[$3])],
       [AC_MSG_RESULT([yes])
        m4_if([$2], ,:,[$2])
        AC_CHECK_HEADERS([sys/socket.h netinet/in.h byteswap.h])
        AS_IF([test "x${GNUNET_CFLAGS+set}" != "xset"],
              [GNUNET_CFLAGS=`$GNUNET_CONFIG --cflags`
              AC_SUBST([GNUNET_CFLAGS])])
        AS_IF([test "x${GNUNET_LIBS+set}" != "xset"],
              [GNUNET_LIBS=`$GNUNET_CONFIG --libs`
               AC_SUBST([GNUNET_LIBS])])
        AS_IF([test "x$enable_debug_log" = "xno"],
              [AC_DEFINE([GNUNET_EXTRA_LOGGING],
                         [0],
                         [0 if debug messages should be culled])])])
 AS_UNSET([gnunet_result])
 AS_UNSET([min_gnunet_version])
])
