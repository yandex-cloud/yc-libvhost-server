#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "platform.h"
#include "event.h"
#include "logging.h"

enum event_loop_state
{
    EVLOOP_RUNNING = 0,
    EVLOOP_SHOULD_STOP,
    EVLOOP_DESTROYED,
};

struct vhd_event_loop
{
    int epollfd;

    /* eventfd we use to cancel epoll_wait if needed */
    int interruptfd;

    /* event_loop_state values */
    atomic_int state;

    /* vhd_terminate_event_loop has been completed */
    volatile bool is_terminated;

    /* preallocated events buffer */
    struct epoll_event* events;
    size_t max_events;
};

static inline int get_state(struct vhd_event_loop* evloop)
{
    return atomic_load(&evloop->state);
}

static inline bool cas_state(struct vhd_event_loop* evloop, int expected, int desired)
{
    return atomic_compare_exchange_strong(&evloop->state, &expected, desired);
}

static inline bool is_valid(struct vhd_event_loop* evloop)
{
    return evloop && (get_state(evloop) != EVLOOP_DESTROYED);
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
        if (events[i].data.fd == evloop->interruptfd) {
            /* We were interrupted, handle other events normally and ignore this one */
            vhd_clear_eventfd(evloop->interruptfd);
            continue;
        }

        struct vhd_event_ctx* ev = events[i].data.ptr;
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
    ev.data.fd = interruptfd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, interruptfd, &ev) == -1) {
        VHD_LOG_ERROR("Can't add event: %d", errno);
        goto error_out;
    }

    struct vhd_event_loop* evloop = vhd_alloc(sizeof(*evloop));
    evloop->epollfd = epollfd;
    evloop->interruptfd = interruptfd;
    evloop->is_terminated = false;
    evloop->max_events = max_events + 1; /* +1 for interrupt eventfd */
    evloop->events = vhd_calloc(sizeof(evloop->events[0]), evloop->max_events);
    evloop->state = EVLOOP_RUNNING;

    return evloop;

error_out:
    close(interruptfd);
    close(epollfd);
    return NULL;
}

int vhd_run_event_loop(struct vhd_event_loop* evloop, int timeout_ms)
{
    VHD_VERIFY(is_valid(evloop));

    if (get_state(evloop) == EVLOOP_SHOULD_STOP) {
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

    int nerr = handle_events(evloop, nev);
    if (nerr) {
        VHD_LOG_WARN("Got %d events, can't handle %d events", nev, nerr);
        return -EIO;
    }

    return nev;
}

void vhd_interrupt_event_loop(struct vhd_event_loop* evloop)
{
    VHD_VERIFY(is_valid(evloop));
    vhd_set_eventfd(evloop->interruptfd);
}

bool vhd_event_loop_terminated(struct vhd_event_loop* evloop)
{
    VHD_VERIFY(is_valid(evloop));
    return evloop->is_terminated;
}

void vhd_terminate_event_loop(struct vhd_event_loop* evloop)
{
    VHD_VERIFY(is_valid(evloop));

    /* Caller terminates event loop from thread 1 and then waits for event loop to exit in thread 2.
     * After event loop exits in thread 2 caller wants to free it.
     * There is a race condition with vhd_free_event_loop in this scenario if event loop
     * exits _before_ this function completes (due to timeout for example). */
    if (!cas_state(evloop, EVLOOP_RUNNING, EVLOOP_SHOULD_STOP)) {
        /* Event loop already being freed, don't touch it */
        return;
    }

    /* Interrupt any running epoll_wait */
    vhd_interrupt_event_loop(evloop);
    evloop->is_terminated = true;
}

void vhd_free_event_loop(struct vhd_event_loop* evloop)
{
    if (!evloop) {
        return;
    }

    VHD_VERIFY(is_valid(evloop));

    /* See comments about event loop termination race in vhd_terminate_event_loop */
    if (!cas_state(evloop, EVLOOP_RUNNING, EVLOOP_DESTROYED)) {
        /* Wait for running termination to complete */
        while (!evloop->is_terminated) {
            vhd_yield_cpu();
        }

        if (!cas_state(evloop, EVLOOP_SHOULD_STOP, EVLOOP_DESTROYED)) {
            /* We should only see EVLOOP_SHOULD_STOP state now */
            VHD_VERIFY(0);
        }
    }

    close(evloop->epollfd);
    close(evloop->interruptfd);
    vhd_free(evloop->events);
    vhd_free(evloop);
}

int vhd_add_event(struct vhd_event_loop* evloop, int fd, struct vhd_event_ctx* ctx)
{
    VHD_VERIFY(is_valid(evloop));
    VHD_VERIFY(ctx && ctx->ops);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
    ev.data.fd = fd;
    ev.data.ptr = ctx;
    if (epoll_ctl(evloop->epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        VHD_LOG_ERROR("Can't add event: %d", errno);
        return -errno;
    }

    return 0;
}

int vhd_del_event(struct vhd_event_loop* evloop, int fd)
{
    VHD_VERIFY(is_valid(evloop));

    if (epoll_ctl(evloop->epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        VHD_LOG_ERROR("Can't delete event: %d", errno);
        return -errno;
    }

    return 0;
}

void vhd_clear_eventfd(int fd)
{
    eventfd_t unused;
    eventfd_read(fd, &unused);
}

void vhd_set_eventfd(int fd)
{
    eventfd_write(fd, 1);
}
