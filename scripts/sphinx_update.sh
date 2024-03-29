# This is more portable than `which' but comes with
# the caveat of not(?) properly working on busybox's ash:
existence()
{
    type "$1" >/dev/null 2>&1
}

sphinx_update()
{
    echo "Updating handbook..."
    if existence sphinx-build; then
      cwd=$PWD
      cd contrib/handbook || exit 1
      if test -e _build; then
        make clean
      fi
      # GNS
      make html >/dev/null || exit 1
      if test -e ../../doc/handbook/html; then
        rm -r ../../doc/handbook/html || exit 1
      fi
      cp -r _build/html ../../doc/handbook/ || exit 1
      if test -e ../../doc/handbook/texinfo; then
        rm -r ../../doc/handbook/texinfo || exit 1
      fi
      make info >/dev/null || exit 1
      cp -r _build/texinfo ../../doc/handbook/ || exit 1
      cd $cwd
    else
      echo "ERROR: Sphinx not found! Unable to generate recent documentation."
      exit 1
    fi
}

sphinx_update
