# Contributing to libvhost

See [README.md](README.md) for build and test instructions and
[docs/architecture.md](docs/architecture.md) for the project architecture.

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

## Commit messages

- Keep every line of the commit message, including the subject, within 72
  characters. Wrap the body manually; long lines are hard to read in
  `git log` and in review tools. Lines that cannot be wrapped, such as URLs
  or quoted log output, are an exception.

## Tests

- Add unit tests as CUnit tests in `tests/unit/`, registered in the `unit`
  suite. Test vhost-user protocol handling through the minimal client in
  `tests/unit/vdev_test.cpp` rather than by setting internal device state
  directly.
- Add scenarios that need a real frontend doing I/O to the pytest
  integration tests in `tests/test_libvhost.py`.
- Do not add standalone test programs outside these two sets: CI runs only
  the `unit` suite and the pytest tests.
