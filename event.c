/*
 * Based on QEMU's util/async.c
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 * Copyright (c) 2009-2017 QEMU contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "catomic.h"
#include "queue.h"
#include "platform.h"
#include "event.h"
#include "logging.h"

enum {
    /* Already enqueued and waiting for bh_poll() */
    BH_PENDING   = (1 << 0),

    /* Invoke the callback */
    BH_SCHEDULED = (1 << 1),

    /* Delete without invoking callback */
    BH_DELETED   = (1 << 2),

    /* Delete after invoking callback */
    BH_ONESHOT   = (1 << 3),
};

struct vhd_bh {
    struct vhd_event_loop *ctx;
    vhd_bh_cb *cb;
    void *opaque;
    SLIST_ENTRY(vhd_bh) next;
    atomic_uint flags;
};

typedef SLIST_HEAD_ATOMIC(, vhd_bh) vhd_bh_list;

struct vhd_event_loop
{
    int epollfd;

    /* eventfd we use to cancel epoll_wait if needed */
    int interruptfd;
    atomic_bool notified;

    /* vhd_terminate_event_loop has been completed */
    bool is_terminated;

    /* preallocated events buffer */
    struct epoll_event* events;
    size_t max_events;

    vhd_bh_list bh_list;
};

/* called concurrently from any thread */
static void bh_enqueue(struct vhd_bh *bh, unsigned new_flags)
{
    struct vhd_event_loop *ctx = bh->ctx;
    unsigned old_flags;

    /*
     * The memory barrier implicit in atomic_fetch_or makes sure that:
     * 1. any writes needed by the callback are done before the locations are
     *    read in the bh_poll.
     * 2. ctx is loaded before the callback has a chance to execute and bh
     *    could be freed.
     * Paired with bh_dequeue().
     */
    old_flags = atomic_fetch_or(&bh->flags, BH_PENDING | new_flags);
    if (!(old_flags & BH_PENDING)) {
        SLIST_INSERT_HEAD_ATOMIC(&ctx->bh_list, bh, next);
    }

    vhd_interrupt_event_loop(ctx);
}

/* only called from bh_poll() and bh_cleanup() */
static struct vhd_bh *bh_dequeue(vhd_bh_list *head, unsigned *flags)
{
    struct vhd_bh *bh = SLIST_FIRST_RCU(head);

    if (!bh) {
        return NULL;
    }

    SLIST_REMOVE_HEAD(head, next);

    /*
     * The atomic_and is paired with bh_enqueue().  The implicit memory barrier
     * ensures that the callback sees all writes done by the scheduling thread.
     * It also ensures that the scheduling thread sees the cleared flag before
     * bh->cb has run, and thus will call vhd_interrupt_event_loop again if
     * necessary.
     */
    *flags = atomic_fetch_and(&bh->flags, ~(BH_PENDING | BH_SCHEDULED));
    return bh;
}

struct vhd_bh *vhd_bh_new(struct vhd_event_loop *ctx,
                          vhd_bh_cb *cb, void *opaque)
{
    struct vhd_bh *bh = vhd_alloc(sizeof(*bh));
    *bh = (struct vhd_bh){
        .ctx = ctx,
        .cb = cb,
        .opaque = opaque,
    };
    return bh;
}

void vhd_bh_schedule_oneshot(struct vhd_event_loop *ctx,
                             vhd_bh_cb *cb, void *opaque)
{
    struct vhd_bh *bh = vhd_bh_new(ctx, cb, opaque);
    bh_enqueue(bh, BH_SCHEDULED | BH_ONESHOT);
}

void vhd_bh_schedule(struct vhd_bh *bh)
{
    bh_enqueue(bh, BH_SCHEDULED);
}

/* this is async and doesn't interfere with already running bh */
void vhd_bh_cancel(struct vhd_bh *bh)
{
    atomic_and(&bh->flags, ~BH_SCHEDULED);
}

/* this is async; deletion only happens in bh_poll, so need to enqueue first */
void vhd_bh_delete(struct vhd_bh *bh)
{
    bh_enqueue(bh, BH_DELETED);
}


static void bh_call(struct vhd_bh *bh)
{
    bh->cb(bh->opaque);
}

/*
 * Execute bottom halves scheduled so far.  Return true if any progress has
 * been made (i.e. any bh was executed).
 * Multiple occurrences of bh_poll cannot be called concurrently.
 */
static bool bh_poll(struct vhd_event_loop *ctx)
{
    vhd_bh_list bh_list;
    struct vhd_bh *bh;
    unsigned flags;
    bool ret = false;

    SLIST_INIT(&bh_list);
    /* swap bh list from ctx for a fresh one */
    SLIST_MOVE_ATOMIC(&bh_list, &ctx->bh_list);

    for (;;) {
        bh = bh_dequeue(&bh_list, &flags);
        if (!bh) {
            break;
        }

        if ((flags & (BH_SCHEDULED | BH_DELETED)) == BH_SCHEDULED) {
            ret = true;
            bh_call(bh);
        }

        if (flags & (BH_DELETED | BH_ONESHOT)) {
            vhd_free(bh);
        }
    }

    return ret;
}

static void bh_cleanup(struct vhd_event_loop *ctx)
{
    struct vhd_bh *bh;
    unsigned flags;

    for (;;) {
        bh = bh_dequeue(&ctx->bh_list, &flags);
        if (!bh) {
            break;
        }

        /* only deleted bhs may remain */
        assert(flags & BH_DELETED);
        vhd_free(bh);
    }
}

static void notify_accept(struct vhd_event_loop *evloop)
{
    if (atomic_read(&evloop->notified)) {
        vhd_clear_eventfd(evloop->interruptfd);
        atomic_xchg(&evloop->notified, false);
    }
}

static int handle_one_event(struct vhd_event_ctx* ev, int event_code)
{
    if ((event_code & (EPOLLIN | EPOLLERR | EPOLLRDHUP)) && ev->ops->read) {
        return ev->ops->read(ev->priv);
    }

    return 0;
}

static int handle_events(struct vhd_event_loop* evloop, int nevents)
{
    int nerr = 0;
    struct epoll_event* events = evloop->events;

    for (int i = 0; i < nevents; i++) {
        struct vhd_event_ctx* ev = events[i].data.ptr;
        if (!ev) {
            continue;
        }
        if (handle_one_event(ev, events[i].events)) {
            nerr++;
        }
    }

    return nerr;
}

struct vhd_event_loop* vhd_create_event_loop(size_t max_events)
{
    int interruptfd = -1;
    int epollfd = -1;

    epollfd = epoll_create1(0);
    if (epollfd < 0) {
        VHD_LOG_ERROR("Can't create epoll fd: %d", errno);
        goto error_out;
    }

    interruptfd = eventfd(0, EFD_NONBLOCK);
    if (interruptfd < 0) {
        VHD_LOG_ERROR("eventfd() failed: %d", errno);
        goto error_out;
    }

    /* Register interrupt eventfd, make sure it is level-triggered */
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, interruptfd, &ev) == -1) {
        VHD_LOG_ERROR("Can't add event: %d", errno);
        goto error_out;
    }

    struct vhd_event_loop* evloop = vhd_alloc(sizeof(*evloop));
    evloop->epollfd = epollfd;
    evloop->interruptfd = interruptfd;
    atomic_set(&evloop->notified, false);
    evloop->is_terminated = false;
    evloop->max_events = max_events + 1; /* +1 for interrupt eventfd */
    evloop->events = vhd_calloc(sizeof(evloop->events[0]), evloop->max_events);
    SLIST_INIT(&evloop->bh_list);

    return evloop;

error_out:
    close(interruptfd);
    close(epollfd);
    return NULL;
}

int vhd_run_event_loop(struct vhd_event_loop* evloop, int timeout_ms)
{
    if (vhd_event_loop_terminated(evloop)) {
        return 0;
    }

    int nev = epoll_wait(evloop->epollfd, evloop->events, evloop->max_events, timeout_ms);
    if (!nev) {
        return 0;
    } else if (nev < 0) {
        if (errno == EINTR) {
            return 0;
        }

        VHD_LOG_ERROR("epoll_wait internal error: %d", errno);
        return -errno;
    }

    notify_accept(evloop);
    bh_poll(evloop);

    int nerr = handle_events(evloop, nev);
    if (nerr) {
        VHD_LOG_WARN("Got %d events, can't handle %d events", nev, nerr);
        return -EIO;
    }

    return nev;
}

void vhd_interrupt_event_loop(struct vhd_event_loop* evloop)
{
    if (!atomic_xchg(&evloop->notified, true)) {
        vhd_set_eventfd(evloop->interruptfd);
    }
}

bool vhd_event_loop_terminated(struct vhd_event_loop* evloop)
{
    return evloop->is_terminated;
}

void evloop_stop_bh(void *opaque)
{
    struct vhd_event_loop *evloop = opaque;
    evloop->is_terminated = true;
}

void vhd_terminate_event_loop(struct vhd_event_loop* evloop)
{
    vhd_bh_schedule_oneshot(evloop, evloop_stop_bh, evloop);
}

/*
 * Only free the event loop when there's no concurrent access to it.  One way
 * to do it is to do free at the end of the thread running the event loop.
 * Another is to wait for the thread running the event loop to terminate (to
 * join it) and only do free afterwards.
 */
void vhd_free_event_loop(struct vhd_event_loop* evloop)
{
    bh_cleanup(evloop);
    close(evloop->epollfd);
    close(evloop->interruptfd);
    vhd_free(evloop->events);
    vhd_free(evloop);
}

int vhd_add_event(struct vhd_event_loop* evloop, int fd, struct vhd_event_ctx* ctx)
{
    VHD_VERIFY(ctx && ctx->ops);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
    ev.data.ptr = ctx;
    if (epoll_ctl(evloop->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        VHD_LOG_ERROR("Can't add event: %d", errno);
        return -errno;
    }

    return 0;
}

int vhd_del_event(struct vhd_event_loop* evloop, int fd)
{
    if (epoll_ctl(evloop->epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        VHD_LOG_ERROR("Can't delete event: %d", errno);
        return -errno;
    }

    return 0;
}

void vhd_clear_eventfd(int fd)
{
    eventfd_t unused;
    while (eventfd_read(fd, &unused) && errno == EINTR) {
        ;
    }
}

void vhd_set_eventfd(int fd)
{
    while (eventfd_write(fd, 1) && errno == EINTR) {
        ;
    }
}
