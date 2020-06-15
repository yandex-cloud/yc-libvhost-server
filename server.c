#include <pthread.h>

#include "platform.h"
#include "server_internal.h"
#include "queue.h"
#include "event.h"
#include "vhost/blockdev.h"
#include "logging.h"

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

/* TODO: bounded queue */
struct vhd_request_queue
{
    struct vhd_event_loop* evloop;

    /* TODO: RCU lock would have been nice.. */
    pthread_spinlock_t lock;
    TAILQ_HEAD(, vhd_request_entry) requests;
};

struct vhd_request_entry
{
    struct vhd_request data;
    TAILQ_ENTRY(vhd_request_entry) link;
};

struct vhd_request_queue* vhd_create_request_queue(void)
{
    struct vhd_request_queue* rq = vhd_alloc(sizeof(*rq));

    rq->evloop = vhd_create_event_loop(VHD_EVENT_LOOP_DEFAULT_MAX_EVENTS);
    if (!rq->evloop) {
        vhd_free(rq);
        return NULL;
    }

    int res = pthread_spin_init(&rq->lock, PTHREAD_PROCESS_PRIVATE);
    if (res != 0) {
        vhd_release_request_queue(rq);
        return NULL;
    }

    TAILQ_INIT(&rq->requests);
    return rq;
}

void vhd_release_request_queue(struct vhd_request_queue* rq)
{
    if (rq) {
        pthread_spin_destroy(&rq->lock);
        vhd_free_event_loop(rq->evloop);
        vhd_free(rq);
    }
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
    VHD_VERIFY(rq);
    VHD_VERIFY(out_req);

    struct vhd_request_entry* r = NULL;

    pthread_spin_lock(&rq->lock);
    if (!TAILQ_EMPTY(&rq->requests)) {
        r = TAILQ_FIRST(&rq->requests);
        TAILQ_REMOVE(&rq->requests, r, link);
    }
    pthread_spin_unlock(&rq->lock);

    if (!r) {
        return false;
    }

    *out_req = r->data;
    vhd_free(r);

    return true;
}

int vhd_enqueue_request(struct vhd_request_queue* rq, struct vhd_request_entry* r)
{
    pthread_spin_lock(&rq->lock);
    TAILQ_INSERT_TAIL(&rq->requests, r, link);
    pthread_spin_unlock(&rq->lock);

    return 0;
}

int vhd_enqueue_block_request(struct vhd_request_queue* rq, struct vhd_vdev* vdev, struct vhd_bdev_io* bio)
{
    VHD_VERIFY(rq);
    VHD_VERIFY(bio);

    struct vhd_request_entry* r = vhd_zalloc(sizeof(*r));
    r->data.bio = bio;
    r->data.vdev = vdev;

    return vhd_enqueue_request(rq, r);
}
