libaio = cc.find_library('aio', required: true)
libpthread = cc.find_library('pthread', required: true)

vhost_user_blk_test_server_includes = include_directories(
    '../'
)

vhost_user_blk_test_server = executable(
    'vhost-user-blk-test-server',
    'vhost_user_blk_test_server.c',
    link_with: libvhost,
    dependencies: [libaio, libpthread],
    include_directories: [
        vhost_user_blk_test_server_includes,
        libvhost_includes
    ]
)

envdata = environment()
envdata.append(
    'TEST_SERVER_BINARY',
    vhost_user_blk_test_server.full_path()
)

test(
    'unit-tests',
    import('python').find_installation('python3', modules: ['pytest']),
    args: ['-m', 'pytest', '-rsv'],
    depends: vhost_user_blk_test_server,
    env: envdata,
    workdir: meson.current_source_dir(),
    timeout: 150,
    is_parallel: false,
)
