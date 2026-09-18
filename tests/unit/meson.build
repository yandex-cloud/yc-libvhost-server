unit_tests = []
unit_tests_option = get_option('unit-tests')
cunit = dependency('cunit', required: unit_tests_option)
if not cunit.found()
    subdir_done()
endif

if not add_languages('cpp', native: false, required: unit_tests_option)
    subdir_done()
endif

unit_test_dependencies = [cunit, dependency('threads')]
unit_test_args = libvhost_defines + [
    '-Wall',
    '-Wextra',
    '-Werror',
    '-Wno-unused-parameter',
    '-Wno-missing-field-initializers',
]

foreach name : ['event_loop_test', 'virtio/virtq_test', 'virtio/virtio_blk_test']
    unit_test = executable(
        name.split('/')[-1],
        name + '.cpp',
        include_directories: libvhost_includes,
        dependencies: unit_test_dependencies,
        link_with: libvhost,
        cpp_args: unit_test_args,
        override_options: ['cpp_std=c++11'],
    )
    unit_tests += unit_test
    test(name.split('/')[-1], unit_test, suite: 'unit', timeout: 60)
endforeach
