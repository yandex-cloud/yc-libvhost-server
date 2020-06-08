#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "atomic.h"
#include "platform.h"
#include "event.h"
#include "logging.h"

struct vhd_event_loop
{
    int epollfd;

    /* eventfd we use to cancel epoll_wait if needed */
    int interruptfd;
    atomic_bool notified;

    /* vhd_terminate_event_loop has been completed */
    atomic_bool is_terminated;

    /* preallocated events buffer */
    struct epoll_event* events;
    size_t max_events;
};

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
    return atomic_load_acquire(&evloop->is_terminated);
}

void vhd_terminate_event_loop(struct vhd_event_loop* evloop)
{
    atomic_store_release(&evloop->is_terminated, true);
    vhd_interrupt_event_loop(evloop);
}

/*
 * Only free the event loop when there's no concurrent access to it.  One way
 * to do it is to do free at the end of the thread running the event loop.
 * Another is to wait for the thread running the event loop to terminate (to
 * join it) and only do free afterwards.
 */
void vhd_free_event_loop(struct vhd_event_loop* evloop)
{
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
