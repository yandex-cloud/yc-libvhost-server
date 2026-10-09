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

/* Negotiate the features and set up the guest memory */
static void client_setup_device(int sock)
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
}

/* Configure a vring up to the point where SET_VRING_KICK starts it */
static void client_setup_vring(int sock, uint32_t i)
{
    uint64_t base = guest_mem_uva + i * vring_mem_size;
    struct vhost_user_vring_state num = { i, queue_size };
    struct vhost_user_vring_state last_avail = { i, 0 };
    struct vhost_user_vring_addr addr = {};
    uint64_t vring_idx = i;
    int callfd = eventfd(0, EFD_CLOEXEC);
    CU_ASSERT_FATAL(callfd >= 0);

    addr.index = i;
    addr.desc_addr = base;
    addr.avail_addr = base + page_size;
    addr.used_addr = base + 2 * page_size;

    client_request(sock, VHOST_USER_SET_VRING_NUM, num);
    client_request(sock, VHOST_USER_SET_VRING_ADDR, addr);
    client_request(sock, VHOST_USER_SET_VRING_BASE, last_avail);
    client_request(sock, VHOST_USER_SET_VRING_CALL, vring_idx, callfd);

    /* the server keeps its own duplicate */
    close(callfd);
}

/* Send SET_VRING_KICK; with @wait == false the reply is left unread */
static void client_kick_vring(int sock, uint32_t i, bool wait)
{
    uint64_t vring_idx = i;
    int kickfd = eventfd(0, EFD_CLOEXEC);
    CU_ASSERT_FATAL(kickfd >= 0);

    client_send(sock, VHOST_USER_SET_VRING_KICK, &vring_idx, sizeof(vring_idx),
                kickfd, true);
    if (wait) {
        CU_ASSERT_FATAL(client_recv_u64(sock, VHOST_USER_SET_VRING_KICK) == 0);
    }

    /* the server keeps its own duplicate */
    close(kickfd);
}

/* Bring all the vrings of the device into the started and enabled state */
static void client_start_vrings(int sock)
{
    client_setup_device(sock);

    for (uint32_t i = 0; i < num_queues; i++) {
        client_setup_vring(sock, i);
        client_kick_vring(sock, i, true);
        client_set_vring_enable(sock, i, true, true);
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

/*
 * Common environment for the vring stop tests: a blockdev on one request queue
 * with a connected client that has set up the device but started no vrings.
 */
struct stop_test_env {
    char tmpdir[sizeof("/tmp/vhost_vdev_test_XXXXXX")];
    std::string socket_path;
    struct vhd_request_queue *rq;
    std::thread rq_thread;
    struct vhd_vdev *vdev;
    int sock;
    sem_t unregistered;
};

static void stop_test_env_init(struct stop_test_env *env)
{
    struct vhd_bdev_info bdev_info = {};

    strcpy(env->tmpdir, "/tmp/vhost_vdev_test_XXXXXX");
    CU_ASSERT_FATAL(mkdtemp(env->tmpdir) != NULL);
    env->socket_path = std::string(env->tmpdir) + "/vhost.sock";
    sem_init(&env->unregistered, 0, 0);

    bdev_info.serial = "vdev_test";
    bdev_info.socket_path = env->socket_path.c_str();
    bdev_info.block_size = 4096;
    bdev_info.num_queues = num_queues;
    bdev_info.total_blocks = 256;

    CU_ASSERT_FATAL(vhd_start_vhost_server(vhd_log_stderr) == 0);

    env->rq = vhd_create_request_queue();
    CU_ASSERT_FATAL(env->rq != NULL);

    struct vhd_request_queue *rq = env->rq;
    env->rq_thread = std::thread([rq]() {
        while (vhd_run_queue(rq) == -EAGAIN) {
            ;
        }
    });

    env->vdev = vhd_register_blockdev(&bdev_info, &env->rq, 1, NULL);
    CU_ASSERT_FATAL(env->vdev != NULL);

    env->sock = client_connect(env->socket_path.c_str());
    client_setup_device(env->sock);
}

static void stop_test_env_fini(struct stop_test_env *env, bool released)
{
    vhd_stop_queue(env->rq);
    env->rq_thread.join();

    /* a device that failed to go away still uses these, leave them alone */
    if (released) {
        vhd_release_request_queue(env->rq);
        vhd_stop_vhost_server();
    }

    close(env->sock);
    unlink(env->socket_path.c_str());
    rmdir(env->tmpdir);
    sem_destroy(&env->unregistered);
}

/*
 * Runs in the request queue between the vring stop callbacks.  Checks whether
 * the device gets released while a stop callback for one of its vrings is
 * still pending: that callback would then access freed memory.
 */
struct release_probe {
    sem_t *unregistered;
    bool released_early;
    sem_t done;
};

/*
 * With the fix the device is pinned until the pending stop callback runs, so
 * the wait always times out; a release within the timeout means the device was
 * freed under the pending callback.
 */
static constexpr int release_probe_timeout_sec = 1;

static void release_probe_bh(void *opaque)
{
    struct release_probe *probe = (struct release_probe *)opaque;

    probe->released_early = sem_wait_timeout(probe->unregistered,
                                             release_probe_timeout_sec);
    if (probe->released_early) {
        /* keep the final check in the test working */
        sem_post(probe->unregistered);
    }
    sem_post(&probe->done);
}

/* Wait for the probe to finish and check its result */
static void release_probe_check(struct release_probe *probe)
{
    sem_wait(&probe->done);
    CU_ASSERT(!probe->released_early);
    sem_destroy(&probe->done);
}

static bool vdev_has_get_vring_base_pending(struct vhd_vdev *vdev)
{
    return vdev->req == VHOST_USER_GET_VRING_BASE;
}

static bool vdev_has_msg_pending(struct vhd_vdev *vdev)
{
    return vdev->num_vrings_handling_msg == 1;
}

static bool vdev_is_disconnected(struct vhd_vdev *vdev)
{
    return vdev->conn_handler == NULL;
}

/*
 * GET_VRING_BASE and the disconnect on unregister both schedule a stop of the
 * same vring.  The second stop callback must not run on a released device.
 *
 * BHs scheduled while the request queue is stalled run in LIFO order, so the
 * request queue sees: the disconnect stop, the release probe, the
 * GET_VRING_BASE stop.
 */
static void get_vring_base_vs_disconnect_test(void)
{
    struct stop_test_env env;
    struct rq_stall stall;
    struct release_probe probe = { &env.unregistered, false, {} };
    struct vhost_user_vring_state state = { 0, 0 };

    stop_test_env_init(&env);
    sem_init(&probe.done, 0, 0);
    sem_init(&stall.entered, 0, 0);
    sem_init(&stall.release, 0, 0);

    client_setup_vring(env.sock, 0);
    client_kick_vring(env.sock, 0, true);

    vhd_run_in_rq(env.rq, rq_stall_bh, &stall);
    sem_wait(&stall.entered);

    /* schedules the first stop; the reply only comes once drained */
    client_send(env.sock, VHOST_USER_GET_VRING_BASE, &state, sizeof(state));
    wait_in_ctl(env.vdev, vdev_has_get_vring_base_pending);

    vhd_run_in_rq(env.rq, release_probe_bh, &probe);

    /* schedules the second stop (before the fix) */
    std::thread unregister_thread([&]() {
        vhd_unregister_blockdev(env.vdev, unregister_complete,
                                &env.unregistered);
    });
    wait_in_ctl(env.vdev, vdev_is_disconnected);

    sem_post(&stall.release);
    unregister_thread.join();

    release_probe_check(&probe);

    bool released = sem_wait_timeout(&env.unregistered, 5);
    CU_ASSERT(released);

    stop_test_env_fini(&env, released);
    sem_destroy(&stall.entered);
    sem_destroy(&stall.release);
}

/*
 * The disconnect on unregister schedules a stop of a vring whose start is
 * still pending.  The start then fails as the device is going down and the
 * vring is marked stopped and drained by the control plane.  The pending stop
 * callback must not run on a released device.
 *
 * Two stalls are needed to make the start run before the stop:
 *   batch 1 (LIFO): stall #2, start  -- the disconnect happens during stall #2
 *   batch 2 (LIFO): release probe, disconnect stop
 */
static void failed_start_vs_disconnect_test(void)
{
    struct stop_test_env env;
    struct rq_stall stall1, stall2;
    struct release_probe probe = { &env.unregistered, false, {} };

    stop_test_env_init(&env);
    sem_init(&probe.done, 0, 0);
    sem_init(&stall1.entered, 0, 0);
    sem_init(&stall1.release, 0, 0);
    sem_init(&stall2.entered, 0, 0);
    sem_init(&stall2.release, 0, 0);

    client_setup_vring(env.sock, 0);

    vhd_run_in_rq(env.rq, rq_stall_bh, &stall1);
    sem_wait(&stall1.entered);

    /* the start is queued to the stalled request queue */
    client_kick_vring(env.sock, 0, false);
    wait_in_ctl(env.vdev, vdev_has_msg_pending);

    /* runs before the start within the next batch */
    vhd_run_in_rq(env.rq, rq_stall_bh, &stall2);
    sem_post(&stall1.release);
    sem_wait(&stall2.entered);

    /* sets ->disconnecting and schedules the stop into the next batch */
    std::thread unregister_thread([&]() {
        vhd_unregister_blockdev(env.vdev, unregister_complete,
                                &env.unregistered);
    });
    wait_in_ctl(env.vdev, vdev_is_disconnected);

    vhd_run_in_rq(env.rq, release_probe_bh, &probe);

    /* the start fails now, and the control plane may release the device */
    sem_post(&stall2.release);
    unregister_thread.join();

    release_probe_check(&probe);

    bool released = sem_wait_timeout(&env.unregistered, 5);
    CU_ASSERT(released);

    stop_test_env_fini(&env, released);
    sem_destroy(&stall1.entered);
    sem_destroy(&stall1.release);
    sem_destroy(&stall2.entered);
    sem_destroy(&stall2.release);
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
    CU_ADD_TEST(suite, get_vring_base_vs_disconnect_test);
    CU_ADD_TEST(suite, failed_start_vs_disconnect_test);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    res = CU_get_error() || CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    return res;
}
