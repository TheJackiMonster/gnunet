dnl
dnl CHECK_LATEX_PACKAGE(FEATURE-NAME,
dnl                     PACKAGE-NAME,
dnl                     ACTION-IF-FOUND,
dnl                     ACTION-IF-NOT-FOUND)
dnl
dnl Tries to compile a small LaTeX document to see if the requested package is
dnl available to be used with \usepackage.
dnl
dnl The result will be cached in the ac_cv_tex_PACKAGE-NAME variable.
dnl
dnl This macro also checks for pdflatex as in AC_CHECK_PROGS and the result
dnl is made available in the PDFLATEX_BINARY variable (all capitals like that.)
dnl
dnl FEATURE-NAME is one or more words to identify the check;
dnl PACKAGE-NAME is the package as it appears in the \usepackage statement
dnl ACTION-IF-FOUND (optional) commands to execute if the package is installed
dnl ACTION-IF-NOT-FOUND (optional) the inverse of ACTION-IF-FOUND
dnl
AC_DEFUN([CHECK_LATEX_PACKAGE],
[AC_CHECK_PROGS([PDFLATEX_BINARY], [pdflatex], [no])

 AS_IF([test "x$ac_cv_prog_PDFLATEX_BINARY" = "xno"],
   [m4_if([$4], ,:,[$4])],
   [AC_CACHE_CHECK([for the $1 package for LaTeX], [AS_TR_SH([ac_cv_tex_][$2])],
      [cat <<EOF > conftest.tex
\\documentclass{article}
\\usepackage{$2}
\\begin{document}
Hello
\\end{document}
EOF

       "$ac_cv_prog_PDFLATEX_BINARY" conftest.tex 1>/dev/null 2>&1
       AS_IF([test "x$?" = "x0"],
         [AS_VAR_SET([AS_TR_SH([ac_cv_tex_][$2])], [yes])],
	 [AS_VAR_SET([AS_TR_SH([ac_cv_tex_][$2])], [no])])])

    AS_VAR_IF([AS_TR_SH([ac_cv_tex_][$2])], [xyes],
      [m4_if([$3], ,:,[$3])],
      [m4_if([$4], ,:,[$4])])])
])dnl
