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
#include "vhost_spec.h"

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

static int read_config_change_msg(int fd)
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

    if (hdr.flags != VHOST_USER_MSG_VERSION) {
        fprintf(stderr, "unexpected flags 0x%x\n", hdr.flags);
        return -1;
    }

    if (hdr.size != 0) {
        fprintf(stderr, "unexpected payload size %u\n", hdr.size);
        return -1;
    }

    return 0;
}

static void init_notify_vdev(struct vhd_vdev *vdev, int slave_req_fd,
                             uint64_t protocol_features)
{
    memset(vdev, 0, sizeof(*vdev));
    vdev->log_tag = "config-change-test";
    vdev->conn_handler = (struct vhd_io_handler *)1;
    vdev->slave_req_fd = slave_req_fd;
    vdev->negotiated_protocol_features = protocol_features;
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
        (1UL << VHOST_USER_PROTOCOL_F_CONFIG) |
        (1UL << VHOST_USER_PROTOCOL_F_SLAVE_REQ));

    if (vhd_vdev_notify_config_change(&vdev) != 0) {
        fprintf(stderr, "vhd_vdev_notify_config_change failed\n");
        goto out;
    }

    ret = read_config_change_msg(sockets[1]);

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
    char byte;

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

    if (recv(sockets[1], &byte, sizeof(byte), 0) >= 0) {
        fprintf(stderr, "unexpected config-change message\n");
        goto out;
    }

    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "unexpected recv error: %s\n", strerror(errno));
        goto out;
    }

    ret = 0;

out:
    close(sockets[0]);
    close(sockets[1]);
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

    if (test_notify_skips_without_negotiated_features() != 0) {
        goto out;
    }

    ret = 0;

out:
    vhd_stop_vhost_server();
    return ret;
}
