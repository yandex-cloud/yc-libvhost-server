#include <pthread.h>

#include "platform.h"
#include "server_internal.h"
#include "queue.h"
#include "vhost/blockdev.h"
#include "bio.h"
#include "logging.h"
#include "vdev.h"

#define VHOST_EVENT_LOOP_EVENTS 128

static struct vhd_event_loop* g_vhost_evloop;
static pthread_t g_vhost_thread;

static inline void free_vhost_event_loop(void)
{
    vhd_free_event_loop(g_vhost_evloop);
    g_vhost_evloop = NULL;
}

static void* vhost_evloop_func(void* arg)
{
    VHD_UNUSED(arg);

    while (!vhd_event_loop_terminated(g_vhost_evloop)) {
        int res = vhd_run_event_loop(g_vhost_evloop, -1);
        if (res < 0) {
            VHD_LOG_ERROR("vhost event loop iteration failed: %d", res);
            break;
        }
    }

    return NULL;
}

int vhd_start_vhost_server(log_function log_fn)
{
    if (g_vhost_evloop != NULL) {
        return 0;
    }

    g_log_fn = log_fn;

    g_vhost_evloop = vhd_create_event_loop(VHOST_EVENT_LOOP_EVENTS);
    if (!g_vhost_evloop) {
        VHD_LOG_ERROR("failed to create vhost event loop");
        return -EIO;
    }

    int res = pthread_create(&g_vhost_thread, NULL, vhost_evloop_func, NULL);
    if (res != 0) {
        VHD_LOG_ERROR("failed to start vhost event loop thread: %d", res);
        free_vhost_event_loop();
        return -res;
    }

    return 0;
}

void vhd_stop_vhost_server(void)
{
    if (!g_vhost_evloop) {
        return;
    }

    vhd_terminate_event_loop(g_vhost_evloop);
    pthread_join(g_vhost_thread, NULL);
    free_vhost_event_loop();
}

int vhd_add_vhost_event(int fd, void* priv, const struct vhd_event_ops* ops, struct vhd_event_ctx* ctx)
{
    if (!g_vhost_evloop) {
        return -ENXIO;
    }

    return vhd_make_event(g_vhost_evloop, fd, priv, ops, ctx);
}

void vhd_del_vhost_event(int fd)
{
    if (!g_vhost_evloop) {
        return;
    }

    vhd_del_event(g_vhost_evloop, fd);
}

////////////////////////////////////////////////////////////////////////////////

//
// Request queues
//

typedef SLIST_HEAD_ATOMIC(, vhd_bio) vhd_bio_list;

/* TODO: bounded queue */
struct vhd_request_queue
{
    struct vhd_event_loop* evloop;

    TAILQ_HEAD(, vhd_bio) submission;

    vhd_bio_list completion;
    struct vhd_bh *completion_bh;
};

void vhd_run_in_rq(struct vhd_request_queue *rq, void (*cb)(void *), void *opaque)
{
    vhd_bh_schedule_oneshot(rq->evloop, cb, opaque);
}

static void rq_complete_bh(void *opaque)
{
    struct vhd_request_queue *rq = opaque;
    vhd_bio_list bio_list, bio_list_reverse;

    SLIST_INIT(&bio_list);
    SLIST_INIT(&bio_list_reverse);
    /* steal completion list from rq, swap for a fresh one */
    SLIST_MOVE_ATOMIC(&bio_list_reverse, &rq->completion);

    /* the list was filled LIFO, we want the completions FIFO */
    for (;;) {
        struct vhd_bio *bio = SLIST_FIRST(&bio_list_reverse);
        if (!bio) {
            break;
        }
        SLIST_REMOVE_HEAD(&bio_list_reverse, completion_link);
        SLIST_INSERT_HEAD(&bio_list, bio, completion_link);
    }

    for (;;) {
        struct vhd_bio *bio = SLIST_FIRST(&bio_list);
        if (!bio) {
            break;
        }
        SLIST_REMOVE_HEAD(&bio_list, completion_link);

        struct vhd_vdev* vdev = bio->vdev;
        bio->completion_handler(bio);

        vdev_unref(vdev);
    }
}

struct vhd_request_queue* vhd_create_request_queue(void)
{
    struct vhd_request_queue* rq = vhd_alloc(sizeof(*rq));

    rq->evloop = vhd_create_event_loop(VHD_EVENT_LOOP_DEFAULT_MAX_EVENTS);
    if (!rq->evloop) {
        vhd_free(rq);
        return NULL;
    }

    TAILQ_INIT(&rq->submission);

    SLIST_INIT(&rq->completion);
    rq->completion_bh = vhd_bh_new(rq->evloop, rq_complete_bh, rq);
    return rq;
}

void vhd_release_request_queue(struct vhd_request_queue* rq)
{
    assert(TAILQ_EMPTY(&rq->submission));
    assert(SLIST_EMPTY(&rq->completion));
    vhd_bh_delete(rq->completion_bh);
    vhd_free_event_loop(rq->evloop);
    vhd_free(rq);
}

int vhd_attach_event(struct vhd_request_queue* rq, int fd, struct vhd_event_ctx* ev)
{
    if (!rq) {
        return -EINVAL;
    }

    return vhd_add_event(rq->evloop, fd, ev);
}

void vhd_detach_event(struct vhd_request_queue* rq, int fd)
{
    if (!rq) {
        return;
    }

    vhd_del_event(rq->evloop, fd);
}

int vhd_run_queue(struct vhd_request_queue* rq)
{
    VHD_VERIFY(rq);

    int res = vhd_run_event_loop(rq->evloop, -1);
    if (res < 0) {
        VHD_LOG_ERROR("vhd_run_event_loop returned %d", res);
        return res;
    }

    return 0;
}

void vhd_stop_queue(struct vhd_request_queue* rq)
{
    VHD_VERIFY(rq);
    vhd_interrupt_event_loop(rq->evloop);
}

bool vhd_dequeue_request(struct vhd_request_queue* rq, struct vhd_request* out_req)
{
    struct vhd_bio *bio = TAILQ_FIRST(&rq->submission);

    if (!bio) {
        return false;
    }

    TAILQ_REMOVE(&rq->submission, bio, submission_link);

    out_req->vdev = bio->vdev;
    out_req->bio = &bio->bdev_io;

    return true;
}

int vhd_enqueue_block_request(struct vhd_request_queue* rq,
                              struct vhd_vdev* vdev, struct vhd_bio* bio)
{
    bio->rq = rq;
    bio->vdev = vdev;

    vdev_ref(vdev);

    TAILQ_INSERT_TAIL(&rq->submission, bio, submission_link);
    return 0;
}

/*
 * can be called from arbitrary thread; will schedule completion on the rq
 * event loop
 */
void vhd_complete_bio(struct vhd_bdev_io* bdev_io, enum vhd_bdev_io_result status)
{
    struct vhd_bio *bio = containerof(bdev_io, struct vhd_bio, bdev_io);
    struct vhd_request_queue *rq = bio->rq;
    bio->status = status;

    /*
     * if this is not the first completion on the list scheduling the bh can be
     * skipped because the first one must have done so
     */
    if (!SLIST_INSERT_HEAD_ATOMIC(&rq->completion, bio, completion_link)) {
        vhd_bh_schedule(rq->completion_bh);
    }
}
