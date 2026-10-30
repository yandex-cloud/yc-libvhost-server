# Project overview

Libvhost is a library for building vhost-user protocol servers.
See @docs/architecture.md for project architecture.

## Build

Run commands from the repository root:

```sh
CC=clang meson setup build
ninja -C build
```

## Tests

Unit tests require a C++11 compiler and CUnit (`libcunit1-dev` on Debian and
Ubuntu). They run without QEMU or libblkio:

```sh
CC=clang CXX=clang++ meson setup build-unit -Dunit-tests=enabled -Dlibblkio=disabled
meson test -C build-unit --suite unit --print-errorlogs
```

To enable unit tests in an existing build and run all configured tests:

```sh
meson configure build -Dunit-tests=enabled
ninja test -C build
```

Integration tests require libblkio and pytest. Run them with
`meson test -C build --suite integration` in a build configured with libblkio.

## Contributing

Before preparing commits, read and follow @CONTRIBUTING.md.
