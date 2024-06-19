find_library(LIBAIO NAMES aio REQUIRED)

add_executable(vhost-user-blk-test-server vhost_user_blk_test_server.c)
target_include_directories(vhost-user-blk-test-server
    PRIVATE
    ./
    ../  # TODO: remove external directories
)
target_link_libraries(vhost-user-blk-test-server
    vhost-server
    ${LIBAIO}
)
target_compile_options(vhost-user-blk-test-server PRIVATE
    -std=gnu17
    -Wall
    -Werror
    -Wextra
    -Wno-unused-parameter
    -g
    -O2

    -Wno-error=unused-result
)
