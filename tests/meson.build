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
