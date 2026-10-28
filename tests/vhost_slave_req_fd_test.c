#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

#include "test_utils.h"
#include "vdev.h"
#include "vhost/blockdev.h"
#include "vhost_spec.h"

#define TEST_BLOCK_SIZE 4096
#define TEST_TOTAL_BLOCKS 32
#define TEST_PROTOCOL_FEATURES \
    ((1UL << VHOST_USER_PROTOCOL_F_REPLY_ACK) | \
     (1UL << VHOST_USER_PROTOCOL_F_SLAVE_REQ))

struct test_blockdev {
    struct vhd_request_queue *rq;
    struct vhd_vdev *vdev;
    char socket_path[128];
};

static struct vhd_request_queue *g_test_rq;

static int read_all(int fd, void *buf, size_t size)
{
    char *pos = buf;

    while (size) {
        ssize_t ret = recv(fd, pos, size, 0);

        if (ret == 0) {
            return -EPIPE;
        }
        if (ret < 0) {
            return -errno;
        }

        pos += ret;
        size -= ret;
    }

    return 0;
}

static int send_message(int fd, uint32_t req, uint32_t flags,
                        const void *payload, uint32_t size, int sent_fd)
{
    struct vhost_user_msg_hdr hdr = {
        .req = req,
        .flags = flags,
        .size = size,
    };
    struct iovec iov[] = {
        {
            .iov_base = &hdr,
            .iov_len = sizeof(hdr),
        }, {
            .iov_base = (void *)payload,
            .iov_len = size,
        },
    };
    struct msghdr msgh = {
        .msg_iov = iov,
        .msg_iovlen = 2,
    };
    union {
        char buf[CMSG_SPACE(sizeof(sent_fd))];
        struct cmsghdr cmsg_align;
    } control;
    struct cmsghdr *cmsg;
    ssize_t ret;

    if (sent_fd >= 0) {
        msgh.msg_control = &control;
        msgh.msg_controllen = sizeof(control);
        cmsg = CMSG_FIRSTHDR(&msgh);
        cmsg->cmsg_len = CMSG_LEN(sizeof(sent_fd));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), &sent_fd, sizeof(sent_fd));
    }

    ret = sendmsg(fd, &msgh, MSG_NOSIGNAL);
    if (ret < 0) {
        return -errno;
    }
    if ((size_t)ret != sizeof(hdr) + size) {
        return -EIO;
    }

    return 0;
}

static int expect_ack(int fd, uint32_t req)
{
    struct vhost_user_msg_hdr hdr;
    uint64_t status;
    int ret;

    ret = read_all(fd, &hdr, sizeof(hdr));
    if (ret != 0) {
        return ret;
    }

    if (hdr.req != req || hdr.flags != VHOST_USER_MSG_FLAGS_REPLY ||
        hdr.size != sizeof(status)) {
        return -EPROTO;
    }

    ret = read_all(fd, &status, sizeof(status));
    if (ret != 0) {
        return ret;
    }

    return status == 0 ? 0 : -EPROTO;
}

static int init_test_blockdev(struct test_blockdev *dev)
{
    struct vhd_request_queue *rqs[1];
    struct vhd_bdev_info info = {
        .serial = "slave-req-fd-test",
        .block_size = TEST_BLOCK_SIZE,
        .optimal_io_size = TEST_BLOCK_SIZE,
        .num_queues = 1,
        .total_blocks = TEST_TOTAL_BLOCKS,
    };

    memset(dev, 0, sizeof(*dev));
    snprintf(dev->socket_path, sizeof(dev->socket_path),
             "/tmp/vhost-slave-req-fd-test-%ld.sock", (long)getpid());
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

static int connect_client(const char *socket_path)
{
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    struct timeval timeout = {
        .tv_sec = 1,
    };
    int fd;

    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        return -ENAMETOOLONG;
    }

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -errno;
    }

    strcpy(addr.sun_path, socket_path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        int ret = -errno;
        close(fd);
        return ret;
    }

    return fd;
}

static int test_set_slave_req_fd(void)
{
    struct test_blockdev dev;
    uint64_t features = TEST_PROTOCOL_FEATURES;
    int client = -1;
    int slave_req[2] = {-1, -1};
    int fd_flags;
    int ret = -1;

    if (init_test_blockdev(&dev) != 0) {
        return -1;
    }

    client = connect_client(dev.socket_path);
    if (client < 0) {
        fprintf(stderr, "connect failed: %s\n", strerror(-client));
        goto out;
    }

    if (send_message(client, VHOST_USER_SET_PROTOCOL_FEATURES,
                     VHOST_USER_MSG_VERSION, &features, sizeof(features), -1) != 0) {
        fprintf(stderr, "failed to negotiate protocol features\n");
        goto out;
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, slave_req) < 0) {
        fprintf(stderr, "socketpair failed: %s\n", strerror(errno));
        goto out;
    }

    if (send_message(client, VHOST_USER_SET_SLAVE_REQ_FD,
                     VHOST_USER_MSG_VERSION | VHOST_USER_MSG_FLAGS_REPLY_ACK,
                     NULL, 0, slave_req[0]) != 0) {
        fprintf(stderr, "failed to send slave request fd\n");
        goto out;
    }

    if (expect_ack(client, VHOST_USER_SET_SLAVE_REQ_FD) != 0) {
        fprintf(stderr, "SET_SLAVE_REQ_FD was not acknowledged\n");
        goto out;
    }

    if (dev.vdev->slave_req_fd < 0 || dev.vdev->slave_req_fd == slave_req[0]) {
        fprintf(stderr, "server did not duplicate the slave request fd\n");
        goto out;
    }

    fd_flags = fcntl(dev.vdev->slave_req_fd, F_GETFD);
    if (fd_flags < 0 || !(fd_flags & FD_CLOEXEC)) {
        fprintf(stderr, "server slave request fd is not close-on-exec\n");
        goto out;
    }

    close(slave_req[0]);
    slave_req[0] = -1;
    if (fcntl(dev.vdev->slave_req_fd, F_GETFD) < 0) {
        fprintf(stderr, "server did not retain the slave request fd\n");
        goto out;
    }

    ret = 0;

out:
    if (client >= 0) {
        close(client);
    }
    if (slave_req[0] >= 0) {
        close(slave_req[0]);
    }
    if (slave_req[1] >= 0) {
        close(slave_req[1]);
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

    if (test_set_slave_req_fd() == 0) {
        ret = 0;
    }

    cleanup_test_request_queue();
    vhd_stop_vhost_server();
    return ret;
}
