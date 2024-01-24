#include <pthread.h>

#include "platform.h"
#include "server_internal.h"
#include "queue.h"
#include "vhost/blockdev.h"
#include "bio.h"
#include "logging.h"
#include "vdev.h"

#define VHOST_EVENT_LOOP_EVENTS 128

static struct vhd_event_loop *g_vhost_evloop;
static pthread_t g_vhost_thread;

static inline void free_vhost_event_loop(void)
{
    vhd_free_event_loop(g_vhost_evloop);
    g_vhost_evloop = NULL;
}

static void *vhost_evloop_func(void *arg)
{
    int res;

    do {
        res = vhd_run_event_loop(g_vhost_evloop, -1);
    } while (res == -EAGAIN);

    if (res < 0) {
        VHD_LOG_ERROR("vhost event loop iteration failed: %d", res);
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

struct vhd_io_handler *vhd_add_vhost_io_handler(int fd,
                                                int (*read)(void *opaque),
                                                void *opaque)
{
    return vhd_add_io_handler(g_vhost_evloop, fd, read, opaque);
}

void vhd_run_in_ctl(void (*cb)(void *), void *opaque)
{
    vhd_bh_schedule_oneshot(g_vhost_evloop, cb, opaque);
}

int vhd_submit_ctl_work_and_wait(void (*func)(struct vhd_work *, void *),
                                 void *opaque)
{
    return vhd_submit_work_and_wait(g_vhost_evloop, func, opaque);
}

/*////////////////////////////////////////////////////////////////////////////*/

/*
 * Request queues
 */

typedef SLIST_HEAD_ATOMIC(, vhd_bio) vhd_bio_list;

/* TODO: bounded queue */
struct vhd_request_queue {
    struct vhd_event_loop *evloop;

    TAILQ_HEAD(, vhd_bio) submission;

    vhd_bio_list completion;
    struct vhd_bh *completion_bh;
};

void vhd_run_in_rq(struct vhd_request_queue *rq, void (*cb)(void *),
                   void *opaque)
{
    vhd_bh_schedule_oneshot(rq->evloop, cb, opaque);
}

static void req_complete(struct vhd_bio *bio)
{
    /* completion_handler destroys bio. save vring for unref */
    struct vhd_vring *vring = bio->vring;
    bio->completion_handler(bio);
    vhd_vring_dec_in_flight(vring);
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
        req_complete(bio);
    }
}

struct vhd_request_queue *vhd_create_request_queue(void)
{
    struct vhd_request_queue *rq = vhd_alloc(sizeof(*rq));

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

void vhd_release_request_queue(struct vhd_request_queue *rq)
{
    assert(TAILQ_EMPTY(&rq->submission));
    assert(SLIST_EMPTY(&rq->completion));
    vhd_bh_delete(rq->completion_bh);
    vhd_free_event_loop(rq->evloop);
    vhd_free(rq);
}

struct vhd_io_handler *vhd_add_rq_io_handler(struct vhd_request_queue *rq,
                                             int fd, int (*read)(void *opaque),
                                             void *opaque)
{
    return vhd_add_io_handler(rq->evloop, fd, read, opaque);
}

int vhd_run_queue(struct vhd_request_queue *rq)
{
    return vhd_run_event_loop(rq->evloop, -1);
}

void vhd_stop_queue(struct vhd_request_queue *rq)
{
    vhd_terminate_event_loop(rq->evloop);
}

bool vhd_dequeue_request(struct vhd_request_queue *rq,
                         struct vhd_request *out_req)
{
    struct vhd_bio *bio = TAILQ_FIRST(&rq->submission);

    if (!bio) {
        return false;
    }

    TAILQ_REMOVE(&rq->submission, bio, submission_link);

    out_req->vdev = bio->vring->vdev;
    out_req->bio = &bio->bdev_io;

    return true;
}


int vhd_enqueue_block_request(struct vhd_request_queue *rq, struct vhd_bio *bio)
{
    vhd_vring_inc_in_flight(bio->vring);

    TAILQ_INSERT_TAIL(&rq->submission, bio, submission_link);
    return 0;
}

void vhd_cancel_queued_requests(struct vhd_request_queue *rq,
                                const struct vhd_vring *vring)
{
    struct vhd_bio *bio;

    TAILQ_FOREACH(bio, &rq->submission, submission_link) {
        if (unlikely(bio->vring == vring)) {
            struct vhd_bio *next = TAILQ_NEXT(bio, submission_link);
            TAILQ_REMOVE(&rq->submission, bio, submission_link);
            bio->status = VHD_BDEV_CANCELED;
            req_complete(bio);
            bio = next;
        }
    }
}

/*
 * can be called from arbitrary thread; will schedule completion on the rq
 * event loop
 */
void vhd_complete_bio(struct vhd_bdev_io *bdev_io,
                      enum vhd_bdev_io_result status)
{
    struct vhd_bio *bio = containerof(bdev_io, struct vhd_bio, bdev_io);
    struct vhd_request_queue *rq = bio->vring->vdev->rq;
    bio->status = status;

    /*
     * if this is not the first completion on the list scheduling the bh can be
     * skipped because the first one must have done so
     */
    if (!SLIST_INSERT_HEAD_ATOMIC(&rq->completion, bio, completion_link)) {
        vhd_bh_schedule(rq->completion_bh);
    }
}
