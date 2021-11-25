dnl
dnl CHECK-LIBHEADER(FEATURE-NAME, LIB-NAME, LIB-FUNCTION, HEADER-NAME,
dnl                 ACTION-IF-FOUND, ACTION-IF-NOT-FOUND,
dnl                 EXTRA-LDFLAGS, EXTRA-CPPFLAGS)
dnl
dnl FEATURE-NAME        - feature name; library and header files are treated
dnl                       as feature, which we look for
dnl LIB-NAME            - library name as in AC_CHECK_LIB macro
dnl LIB-FUNCTION        - library symbol as in AC_CHECK_LIB macro
dnl HEADER-NAME         - header file name as in AC_CHECK_HEADER
dnl ACTION-IF-FOUND     - when feature is found then execute given action
dnl ACTION-IF-NOT-FOUND - when feature is not found then execute given action
dnl EXTRA-LDFLAGS       - extra linker flags (-L or -l)
dnl EXTRA-CPPFLAGS      - extra C preprocessor flags, e.g. -I/usr/X11R6/include
dnl
dnl
AC_DEFUN([CHECK_LIBHEADER],
[m4_if([$7], ,:,[LDFLAGS="$7 $LDFLAGS"])
 m4_if([$8], ,:,[CPPFLAGS="$8 $CPPFLAGS"])

 AC_CHECK_HEADERS([$4],
   [AC_CHECK_LIB([$2], [$3],
      [eval "HAVE_]AS_TR_SH([$1])[=yes"]
       m4_if([$5], ,:,[$5]),
      [eval "HAVE_]AS_TR_SH([$1])[=no"]
       m4_if([$6], ,:,[$6]))],
   [eval "HAVE_]AS_TR_SH([$1])[=no"]
    m4_if([$6], ,:,[$6]))
])dnl
