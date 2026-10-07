#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string>
#include <thread>

#include <CUnit/Basic.h>

#include "vhost/blockdev.h"
#include "vhost/server.h"

#include "event.h"
#include "server_internal.h"
#include "vdev.h"
#include "vhost_spec.h"

#include "test_utils.h"

static constexpr uint16_t num_queues = 2;
static constexpr uint16_t queue_size = 8;
static constexpr size_t page_size = 4096;

/* desc, avail and used rings take a zero-filled page each */
static constexpr size_t vring_mem_size = 3 * page_size;
static constexpr size_t guest_mem_size = num_queues * vring_mem_size;
/* the library maps the memory on its own and only uses this as a lookup key */
static constexpr uint64_t guest_mem_uva = 0x100000000ull;

/*
 * Minimal vhost-user client
 */

static int client_connect(const char *path)
{
    struct sockaddr_un addr = {};
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    CU_ASSERT_FATAL(sock >= 0);

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    CU_ASSERT_FATAL(connect(sock, (struct sockaddr *)&addr,
                            sizeof(addr)) == 0);
    return sock;
}

static void client_send(int sock, uint32_t req, const void *payload,
                        uint32_t size, int fd = -1, bool need_reply = false)
{
    struct vhost_user_msg_hdr hdr = {};
    struct iovec iov[2];
    struct msghdr msgh = {};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr cmsg_align;
    } control;

    hdr.req = req;
    hdr.flags = VHOST_USER_MSG_VERSION |
                (need_reply ? VHOST_USER_MSG_FLAGS_REPLY_ACK : 0);
    hdr.size = size;

    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len = size;

    msgh.msg_iov = iov;
    msgh.msg_iovlen = 2;

    if (fd >= 0) {
        struct cmsghdr *cmsgh;

        memset(&control, 0, sizeof(control));
        msgh.msg_control = &control;
        msgh.msg_controllen = sizeof(control.buf);
        cmsgh = CMSG_FIRSTHDR(&msgh);
        cmsgh->cmsg_len = CMSG_LEN(sizeof(fd));
        cmsgh->cmsg_level = SOL_SOCKET;
        cmsgh->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsgh), &fd, sizeof(fd));
    }

    CU_ASSERT_FATAL(sendmsg(sock, &msgh, 0) == (ssize_t)(sizeof(hdr) + size));
}

static uint64_t client_recv_u64(int sock, uint32_t req)
{
    struct {
        struct vhost_user_msg_hdr hdr;
        uint64_t u64;
    } __attribute__((packed)) reply;

    CU_ASSERT_FATAL(recv(sock, &reply, sizeof(reply), MSG_WAITALL) ==
                    sizeof(reply));
    CU_ASSERT_FATAL(reply.hdr.req == req);
    CU_ASSERT_FATAL(reply.hdr.size == sizeof(reply.u64));
    return reply.u64;
}

/* Send a request and wait until the server acknowledges handling it */
template <typename T>
static void client_request(int sock, uint32_t req, const T &payload,
                           int fd = -1)
{
    client_send(sock, req, &payload, sizeof(payload), fd, true);
    CU_ASSERT_FATAL(client_recv_u64(sock, req) == 0);
}

static void client_set_vring_enable(int sock, uint32_t index, bool enable,
                                    bool wait)
{
    struct vhost_user_vring_state state = { index, enable };

    client_send(sock, VHOST_USER_SET_VRING_ENABLE, &state, sizeof(state), -1,
                true);
    if (wait) {
        CU_ASSERT_FATAL(client_recv_u64(sock,
                                        VHOST_USER_SET_VRING_ENABLE) == 0);
    }
}

/* Bring all the vrings of the device into the started and enabled state */
static void client_start_vrings(int sock)
{
    uint64_t features;
    struct vhost_user_mem_desc mem = {};
    int memfd;

    client_send(sock, VHOST_USER_GET_FEATURES, NULL, 0);
    features = client_recv_u64(sock, VHOST_USER_GET_FEATURES);
    CU_ASSERT_FATAL(features & (1ull << VHOST_USER_F_PROTOCOL_FEATURES));

    client_send(sock, VHOST_USER_GET_PROTOCOL_FEATURES, NULL, 0);
    features = client_recv_u64(sock, VHOST_USER_GET_PROTOCOL_FEATURES);
    CU_ASSERT_FATAL(features & (1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK));

    /* this is the last request that can't be acknowledged */
    features = 1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK;
    client_send(sock, VHOST_USER_SET_PROTOCOL_FEATURES, &features,
                sizeof(features));

    features = 1ull << VHOST_USER_F_PROTOCOL_FEATURES;
    client_request(sock, VHOST_USER_SET_FEATURES, features);

    memfd = memfd_create("vdev_test_guest_mem", MFD_CLOEXEC);
    CU_ASSERT_FATAL(memfd >= 0);
    CU_ASSERT_FATAL(ftruncate(memfd, guest_mem_size) == 0);

    mem.nregions = 1;
    mem.regions[0].size = guest_mem_size;
    mem.regions[0].user_addr = guest_mem_uva;
    client_request(sock, VHOST_USER_SET_MEM_TABLE, mem, memfd);
    close(memfd);

    for (uint32_t i = 0; i < num_queues; i++) {
        uint64_t base = guest_mem_uva + i * vring_mem_size;
        struct vhost_user_vring_state num = { i, queue_size };
        struct vhost_user_vring_state last_avail = { i, 0 };
        struct vhost_user_vring_addr addr = {};
        uint64_t vring_idx = i;
        int callfd = eventfd(0, EFD_CLOEXEC);
        int kickfd = eventfd(0, EFD_CLOEXEC);
        CU_ASSERT_FATAL(callfd >= 0 && kickfd >= 0);

        addr.index = i;
        addr.desc_addr = base;
        addr.avail_addr = base + page_size;
        addr.used_addr = base + 2 * page_size;

        client_request(sock, VHOST_USER_SET_VRING_NUM, num);
        client_request(sock, VHOST_USER_SET_VRING_ADDR, addr);
        client_request(sock, VHOST_USER_SET_VRING_BASE, last_avail);
        client_request(sock, VHOST_USER_SET_VRING_CALL, vring_idx, callfd);
        client_request(sock, VHOST_USER_SET_VRING_KICK, vring_idx, kickfd);
        client_set_vring_enable(sock, i, true, true);

        /* the server keeps its own duplicates */
        close(callfd);
        close(kickfd);
    }
}

/*
 * Helpers to control the order of events in the library
 */

struct ctl_query {
    struct vhd_vdev *vdev;
    bool (*pred)(struct vhd_vdev *);
};

static void ctl_query_fn(struct vhd_work *work, void *opaque)
{
    struct ctl_query *query = (struct ctl_query *)opaque;
    vhd_complete_work(work, query->pred(query->vdev));
}

/*
 * Wait until @pred holds for @vdev.  The vdev state belongs to the control
 * event loop, so that's where it's evaluated.
 */
static void wait_in_ctl(struct vhd_vdev *vdev, bool (*pred)(struct vhd_vdev *))
{
    struct ctl_query query = { vdev, pred };

    while (!vhd_submit_ctl_work_and_wait(ctl_query_fn, &query)) {
        usleep(1000);
    }
}

struct rq_stall {
    sem_t entered;
    sem_t release;
};

/* Keep the request queue from making progress, as a busy backend would */
static void rq_stall_bh(void *opaque)
{
    struct rq_stall *stall = (struct rq_stall *)opaque;

    sem_post(&stall->entered);
    sem_wait(&stall->release);
}

static void wait_vrings_drained_bh(void *opaque)
{
    wait_in_ctl((struct vhd_vdev *)opaque, [](struct vhd_vdev *vdev) {
        return !vdev->num_vrings_started && !vdev->num_vrings_in_flight;
    });
}

static void unregister_complete(void *opaque)
{
    sem_post((sem_t *)opaque);
}

static bool sem_wait_timeout(sem_t *sem, int seconds)
{
    struct timespec ts;
    int ret;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += seconds;

    do {
        ret = sem_timedwait(sem, &ts);
    } while (ret < 0 && errno == EINTR);

    return ret == 0;
}

/*
 * Unregister the device while a message that has to be synced to the dataplane
 * is still being handled, such that the message is the last thing to complete:
 * after all vrings have acknowledged the stop and have been drained.  The
 * device must still be released.
 */
static void unregister_during_vring_msg_test(void)
{
    char tmpdir[] = "/tmp/vhost_vdev_test_XXXXXX";
    CU_ASSERT_FATAL(mkdtemp(tmpdir) != NULL);
    std::string socket_path = std::string(tmpdir) + "/vhost.sock";

    struct vhd_bdev_info bdev_info = {};
    bdev_info.serial = "vdev_test";
    bdev_info.socket_path = socket_path.c_str();
    bdev_info.block_size = 4096;
    bdev_info.num_queues = num_queues;
    bdev_info.total_blocks = 256;

    struct rq_stall stall;
    sem_t unregistered;
    sem_init(&stall.entered, 0, 0);
    sem_init(&stall.release, 0, 0);
    sem_init(&unregistered, 0, 0);

    CU_ASSERT_FATAL(vhd_start_vhost_server(vhd_log_stderr) == 0);

    struct vhd_request_queue *rq = vhd_create_request_queue();
    CU_ASSERT_FATAL(rq != NULL);

    std::thread rq_thread([&]() {
        while (vhd_run_queue(rq) == -EAGAIN) {
            ;
        }
    });

    struct vhd_vdev *vdev = vhd_register_blockdev(&bdev_info, &rq, 1, NULL);
    CU_ASSERT_FATAL(vdev != NULL);

    int sock = client_connect(socket_path.c_str());
    client_start_vrings(sock);

    vhd_run_in_rq(rq, rq_stall_bh, &stall);
    sem_wait(&stall.entered);

    /* this can't complete until the request queue gets to run */
    client_set_vring_enable(sock, 0, false, false);
    wait_in_ctl(vdev, [](struct vhd_vdev *vdev) {
        return vdev->num_vrings_handling_msg == 1;
    });

    /*
     * BHs scheduled while the request queue is stalled are run in LIFO order,
     * so this one goes after the vrings are stopped by the unregister below
     * but before the message above is handled, and holds off the latter until
     * the control event loop is done with the former.
     */
    vhd_run_in_rq(rq, wait_vrings_drained_bh, vdev);

    std::thread unregister_thread([&]() {
        vhd_unregister_blockdev(vdev, unregister_complete, &unregistered);
    });
    wait_in_ctl(vdev, [](struct vhd_vdev *vdev) {
        return vdev->conn_handler == NULL;
    });

    sem_post(&stall.release);
    unregister_thread.join();

    bool released = sem_wait_timeout(&unregistered, 5);
    CU_ASSERT(released);

    vhd_stop_queue(rq);
    rq_thread.join();

    /* a device that failed to go away still uses these, leave them alone */
    if (released) {
        vhd_release_request_queue(rq);
        vhd_stop_vhost_server();
    }

    close(sock);
    unlink(socket_path.c_str());
    rmdir(tmpdir);
    sem_destroy(&stall.entered);
    sem_destroy(&stall.release);
    sem_destroy(&unregistered);
}

int main(void)
{
    int res = 0;
    CU_pSuite suite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    suite = CU_add_suite("vdev_test", NULL, NULL);
    if (NULL == suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_ADD_TEST(suite, unregister_during_vring_msg_test);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    res = CU_get_error() || CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    return res;
}
