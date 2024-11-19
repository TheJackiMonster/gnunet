# Meson build system

DISCLAIMER: This is a work in progress. The meson build system will be maintained for now alongside autotools.

## Motivation

  - We want to build a single, monolithic library libgnunet that is easier to use in, for example, mobile apps.
  - Autotools is complex and difficult to use. It also causes stale builds. Meson has a better developer experience.
  - Meson supports dynamic pkg-config generation.
  - Meson makes it (almost) impossible to create dist tarballs that miss files/do not compile.


## Reasons to drop it again

  - Meson does not seem to support (automatic) dependency version detection without pkg-config.
  - Our autotools logic may already be too complex
  - All tests are always built: https://github.com/mesonbuild/meson/pull/6511
  - We need to keep autotools and meson soversion in sync

## TODOs

  - Migrate remaining tests and targets
  - Some (experimental) subsystems not yet fully ported.
  - 1:1 match of installed files must be verified.
  - Documentation must be updated.

## Use

To compile run:

```
$ meson setup $builddir
$ cd $builddir
$ meson configure -Dprefix=$PFX -Dexperimental=$BOOL
$ meson compile
```

to install:

```
$ meson install
```

to make tarball (runs tests unless specified to skip):

```
$ meson dist
```

to uninstall:

```
$ ninja uninstall
```

to update i18n po files (see also https://mesonbuild.com/i18n-module.html):

```
$ meson gnunet-pot
$ meson gnunet-update-po
$ meson gnunet-gmo

## Test

You can run the tests as:

```
$ meson test
```

you can run individual tests as:

```
$ meson test $TESTNAME
```

for example:


```
$ meson test test_gnsrecord_crypto
```

you can run test suites for components as:


```
$ meson test --suite util
```

performance tests are not included by default, you can run performance tests with the `perf` suite.
Alternative, to also have performance tests available use the `full` setup:

```
$ meson test --setup full
```

You can use this switch also when running suites or individual tests.


