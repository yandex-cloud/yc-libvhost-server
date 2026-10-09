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

## Organizing changes into commits

- Plan a series of focused commits from the outset. Do not bundle independent
  changes, as in this case a reviewer will request a split anyway.
- Each commit should solve one specific problem or make one coherent change.
  Sharing a task, subsystem, file, or function is not a reason to combine
  independent fixes. A small diff is not a reason to combine them either.
- Keep independent bug fixes, standalone refactorings, optimizations, and
  cosmetic changes in separate commits. Changes with different motivations and
  different failure scenarios usually need separate commits.
- Split by purpose, not mechanically by file or hunk. Keep related changes and
  documentation close together in the commit series.
- Do not mix tests with a bug fix or feature implementation in the same commit.
  Put tests in a separate commit after the corresponding fix or feature, so they
  pass when introduced.
- Order commits by their dependencies. The build and tests must pass at every
  commit. Do not introduce intermediate breakage with the intention of fixing
  it in a later commit.
- Explain the specific problem and how the change addresses it in each commit
  message. If a message needs several independent explanations, reconsider the
  commit boundaries.
