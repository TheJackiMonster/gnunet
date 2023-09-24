# Meson build system

DISCLAIMER: This is a work in progress. The meson build system will be maintained for a brief period alongside autotools.

## Motivation

  - We want to build a single, monolithic library libgnunet that is easier to use in, for example, mobile apps.
  - Autotools is complex and difficult to use. It also causes stale builds. Meson has a better developer experience.
  - Meson supports dynamic pkg-config generation.
  - Meson does out-of-tree builds
  - Meson makes it (almost) impossible to create dist tarballs that miss files/do not compile.


## Reasons to drop it again

  - Meson does not seem to support (automatic) dependency version detection without pkg-config.


## TODOs

  - Migrate tests
  - Portability defines set implicitly in configure.ac need to be identified and ported to meson.
  - Some (experimental) subsystems not yet ported.
  - 1:1 match of installed files must be verified.
  - Documentation must be updated.

## Use


```
$ meson setup $builddir
$ cd $builddir
$ meson configure -Dprefix=$string -Dexperimental=$bool -Dmonolith=$bool
$ meson compile
$ meson install
$ meson dist
```
