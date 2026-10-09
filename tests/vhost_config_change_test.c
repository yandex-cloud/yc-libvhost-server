#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_utils.h"
#include "vdev.h"
#include "vhost/blockdev.h"
#include "vhost_spec.h"

#define TEST_BLOCK_SIZE 4096
#define TEST_INITIAL_BLOCKS 32
#define TEST_RESIZED_BLOCKS 64
#define TEST_PROTOCOL_FEATURES \
    ((1UL << VHOST_USER_PROTOCOL_F_CONFIG) | \
     (1UL << VHOST_USER_PROTOCOL_F_SLAVE_REQ))

struct test_blockdev {
    struct vhd_request_queue *rq;
    struct vhd_vdev *vdev;
    char socket_path[128];
};

static struct vhd_request_queue *g_test_rq;

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -errno;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -errno;
    }

    return 0;
}

static int expect_no_data(int fd)
{
    char byte;

    if (recv(fd, &byte, sizeof(byte), 0) >= 0) {
        fprintf(stderr, "unexpected config-change message\n");
        return -1;
    }

    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "unexpected recv error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int read_config_change_msg(int fd, uint32_t expected_flags)
{
    struct vhost_user_msg_hdr hdr;
    ssize_t ret = recv(fd, &hdr, sizeof(hdr), 0);

    if (ret < 0) {
        fprintf(stderr, "recv failed: %s\n", strerror(errno));
        return -1;
    }

    if ((size_t)ret != sizeof(hdr)) {
        fprintf(stderr, "recv returned %zd bytes, expected %zu\n",
                ret, sizeof(hdr));
        return -1;
    }

    if (hdr.req != VHOST_USER_SLAVE_CONFIG_CHANGE_MSG) {
        fprintf(stderr, "unexpected request %u\n", hdr.req);
        return -1;
    }

    if (hdr.flags != expected_flags) {
        fprintf(stderr, "unexpected flags 0x%x\n", hdr.flags);
        return -1;
    }

    if (hdr.size != 0) {
        fprintf(stderr, "unexpected payload size %u\n", hdr.size);
        return -1;
    }

    return 0;
}

static void enable_notify_vdev(struct vhd_vdev *vdev, int slave_req_fd,
                               uint64_t protocol_features)
{
    vdev->conn_handler = (struct vhd_io_handler *)1;
    vdev->slave_req_fd = slave_req_fd;
    vdev->negotiated_protocol_features = protocol_features;
}

static void disable_notify_vdev(struct vhd_vdev *vdev)
{
    vdev->conn_handler = NULL;
    vdev->slave_req_fd = -1;
    vdev->negotiated_protocol_features = 0;
}

static void init_notify_vdev(struct vhd_vdev *vdev, int slave_req_fd,
                             uint64_t protocol_features)
{
    memset(vdev, 0, sizeof(*vdev));
    vdev->log_tag = "config-change-test";
    enable_notify_vdev(vdev, slave_req_fd, protocol_features);
}

static int init_test_blockdev(struct test_blockdev *dev)
{
    struct vhd_request_queue *rqs[1];
    struct vhd_bdev_info info = {
        .serial = "config-change-test",
        .block_size = TEST_BLOCK_SIZE,
        .optimal_io_size = TEST_BLOCK_SIZE,
        .num_queues = 1,
        .total_blocks = TEST_INITIAL_BLOCKS,
    };

    memset(dev, 0, sizeof(*dev));
    snprintf(dev->socket_path, sizeof(dev->socket_path),
             "/tmp/vhost-config-change-test-%ld.sock", (long)getpid());
    unlink(dev->socket_path);
    info.socket_path = dev->socket_path;

    if (!g_test_rq) {
        g_test_rq = vhd_create_request_queue();
        if (!g_test_rq) {
            fprintf(stderr, "vhd_create_request_queue failed\n");
            return -1;
        }
    }

    dev->rq = g_test_rq;
    rqs[0] = dev->rq;
    dev->vdev = vhd_register_blockdev(&info, rqs, 1, NULL);
    if (!dev->vdev) {
        fprintf(stderr, "vhd_register_blockdev failed\n");
        return -1;
    }

    return 0;
}

static void cleanup_test_blockdev(struct test_blockdev *dev)
{
    if (dev->vdev) {
        disable_notify_vdev(dev->vdev);
        vhd_unregister_blockdev(dev->vdev, NULL, NULL);
    }
    if (dev->socket_path[0]) {
        unlink(dev->socket_path);
    }
}

static void cleanup_test_request_queue(void)
{
    if (!g_test_rq) {
        return;
    }

    vhd_stop_queue(g_test_rq);
    vhd_run_queue(g_test_rq);
    vhd_release_request_queue(g_test_rq);
    g_test_rq = NULL;
}

static int test_notify_config_change(void)
{
    struct vhd_vdev vdev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        return -1;
    }

    if (set_nonblock(sockets[1]) < 0) {
        fprintf(stderr, "failed to set nonblocking mode: %s\n", strerror(errno));
        goto out;
    }

    init_notify_vdev(&vdev, sockets[0],
        TEST_PROTOCOL_FEATURES);

    if (vhd_vdev_notify_config_change(&vdev) != 0) {
        fprintf(stderr, "vhd_vdev_notify_config_change failed\n");
        goto out;
    }

    ret = read_config_change_msg(sockets[1], VHOST_USER_MSG_VERSION);

out:
    close(sockets[0]);
    close(sockets[1]);
    return ret;
}

static int test_notify_skips_without_negotiated_features(void)
{
    struct vhd_vdev vdev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        return -1;
    }

    if (set_nonblock(sockets[1]) < 0) {
        fprintf(stderr, "failed to set nonblocking mode: %s\n", strerror(errno));
        goto out;
    }

    init_notify_vdev(&vdev, sockets[0], 0);

    if (vhd_vdev_notify_config_change(&vdev) != 0) {
        fprintf(stderr, "vhd_vdev_notify_config_change failed\n");
        goto out;
    }

    if (expect_no_data(sockets[1]) != 0) {
        goto out;
    }

    ret = 0;

out:
    close(sockets[0]);
    close(sockets[1]);
    return ret;
}

static int test_notify_config_change_returns_send_error(void)
{
    struct vhd_vdev vdev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        return -1;
    }

    init_notify_vdev(&vdev, sockets[0],
        TEST_PROTOCOL_FEATURES);

    close(sockets[1]);
    sockets[1] = -1;

    if (vhd_vdev_notify_config_change(&vdev) == 0) {
        fprintf(stderr, "vhd_vdev_notify_config_change unexpectedly succeeded\n");
        goto out;
    }

    ret = 0;

out:
    close(sockets[0]);
    return ret;
}

static int test_blockdev_set_total_blocks_does_not_notify(void)
{
    struct test_blockdev dev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (init_test_blockdev(&dev) != 0) {
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        goto out;
    }

    if (set_nonblock(sockets[1]) < 0) {
        fprintf(stderr, "failed to set nonblocking mode: %s\n", strerror(errno));
        goto out;
    }

    enable_notify_vdev(dev.vdev, sockets[0], TEST_PROTOCOL_FEATURES);

    vhd_blockdev_set_total_blocks(dev.vdev, TEST_RESIZED_BLOCKS);
    ret = expect_no_data(sockets[1]);

out:
    if (sockets[0] >= 0) {
        close(sockets[0]);
    }
    if (sockets[1] >= 0) {
        close(sockets[1]);
    }
    cleanup_test_blockdev(&dev);
    return ret;
}

static int test_blockdev_resize_notifies_config_change(void)
{
    struct test_blockdev dev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (init_test_blockdev(&dev) != 0) {
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        goto out;
    }

    enable_notify_vdev(dev.vdev, sockets[0], TEST_PROTOCOL_FEATURES);

    if (vhd_blockdev_resize(dev.vdev, TEST_RESIZED_BLOCKS) != 0) {
        fprintf(stderr, "vhd_blockdev_resize failed\n");
        goto out;
    }

    ret = read_config_change_msg(sockets[1], VHOST_USER_MSG_VERSION);

out:
    if (sockets[0] >= 0) {
        close(sockets[0]);
    }
    if (sockets[1] >= 0) {
        close(sockets[1]);
    }
    cleanup_test_blockdev(&dev);
    return ret;
}

static int test_blockdev_resize_returns_send_error(void)
{
    struct test_blockdev dev;
    int sockets[2] = {-1, -1};
    int ret = -1;

    if (init_test_blockdev(&dev) != 0) {
        return -1;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        goto out;
    }

    enable_notify_vdev(dev.vdev, sockets[0], TEST_PROTOCOL_FEATURES);

    close(sockets[1]);
    sockets[1] = -1;

    if (vhd_blockdev_resize(dev.vdev, TEST_RESIZED_BLOCKS) == 0) {
        fprintf(stderr, "vhd_blockdev_resize unexpectedly succeeded\n");
        goto out;
    }

    ret = 0;

out:
    if (sockets[0] >= 0) {
        close(sockets[0]);
    }
    cleanup_test_blockdev(&dev);
    return ret;
}

int main(void)
{
    int ret = 1;

    if (vhd_start_vhost_server(vhd_log_stderr) != 0) {
        fprintf(stderr, "failed to start vhost server\n");
        return 1;
    }

    if (test_notify_config_change() != 0) {
        goto out;
    }

    if (test_notify_config_change_returns_send_error() != 0) {
        goto out;
    }

    if (test_notify_skips_without_negotiated_features() != 0) {
        goto out;
    }

    if (test_blockdev_set_total_blocks_does_not_notify() != 0) {
        goto out;
    }

    if (test_blockdev_resize_notifies_config_change() != 0) {
        goto out;
    }

    if (test_blockdev_resize_returns_send_error() != 0) {
        goto out;
    }

    ret = 0;

out:
    cleanup_test_request_queue();
    vhd_stop_vhost_server();
    return ret;
}
