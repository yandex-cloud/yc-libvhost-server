<div style="display: flex; align-items: center;">
  <img style="margin-bottom: 5px;" src="docs/logo.svg" width="40px" align="left"/>
  <h1 style="margin-left: 5px; margin-bottom: 5px;">Libvhost</h1>
</div>

[![CI](https://github.com/yandex-cloud/yc-libvhost-server/actions/workflows/main.yaml/badge.svg)](https://github.com/yandex-cloud/yc-libvhost-server/actions/workflows/main.yaml)

A library for building [vhost-user protocol](https://qemu-project.gitlab.io/qemu/interop/vhost-user.html) servers.

## Quickstart

Building the project:
```bash
CC=clang meson setup build
ninja -C build
```

Running tests locally (unit tests require a C++11 compiler and CUnit, provided
by `libcunit1-dev` on Debian and Ubuntu):
```
meson configure build -Dunit-tests=enabled
ninja test -C build
```

Unit tests run without QEMU or libblkio. To build and run only these tests:
```bash
CC=clang CXX=clang++ meson setup build-unit -Dunit-tests=enabled -Dlibblkio=disabled
meson test -C build-unit --suite unit --print-errorlogs
```

The `unit-tests` option defaults to `auto`: unit tests are built when CUnit and
a C++ compiler are available. Use `-Dunit-tests=enabled` to require them or
`-Dunit-tests=disabled` to skip them. Integration tests require libblkio and
pytest and can be selected with `meson test -C build --suite integration`.
