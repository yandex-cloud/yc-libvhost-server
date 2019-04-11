// TODO list:
// * Dynamic event fd vector instead of fixed event array
// * Timeout argument in run
// * Thread-safe event source add/remove

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "vhost-server/platform.h"
#include "vhost-server/event.h"

#define VHD_MAX_EVENTS              128
#define VHD_MAX_EPOLL_TIMEOUT_MS    1000
#define VHD_EPOLL_EVENTS            (EPOLLIN | EPOLLHUP | EPOLLRDHUP)

/*
 * epoll fd for global event loop
 */
static int g_event_loop_fd = -1;

static int handle_one_event(struct vhd_event_ctx* ev, int event_code)
{
    VHD_ASSERT(ev);
    VHD_ASSERT(ev->ops);

    int ret = 0;
    if ((event_code & EPOLLERR) || (event_code & (EPOLLHUP | EPOLLRDHUP))) {
        if (ev->ops->close) {
            ret = ev->ops->close(ev->priv);
        }
    } else if (event_code == EPOLLIN) {
        if (ev->ops->read) {
            ret = ev->ops->read(ev->priv);
        }
    }

    return ret;
}

static int handle_events(struct epoll_event *events, int nevents)
{
    int nerr = 0;
    for (int i = 0; i < nevents; i++) {
        struct vhd_event_ctx* ev = events[i].data.ptr;
        if (handle_one_event(ev, events[i].events)) {
            nerr++;
        }
    }

    return nerr;
}

int vhd_init_event_loop(void)
{
    if (g_event_loop_fd >= 0) {
        return EBUSY;
    }

    int fd = epoll_create1(0);
    if (fd == -1) {
        VHD_LOG_ERROR("Can't create epoll fd: %d", errno);
        return errno;
    }

    g_event_loop_fd = fd;
    return 0;
}

int vhd_run_event_loop(void)
{
    if (!g_event_loop_fd) {
        return ENXIO;
    }

    struct epoll_event events[VHD_MAX_EVENTS];
    int nev = epoll_wait(g_event_loop_fd, events, VHD_MAX_EVENTS, VHD_MAX_EPOLL_TIMEOUT_MS);
    if (!nev) {
        return 0;
    } else if (nev == -1) {
        VHD_LOG_ERROR("epoll_wait internal error: %d", errno);
        return nev;
    }

    int nerr = handle_events(events, nev);
    if (nerr) {
        VHD_LOG_WARN("Got %d events, can't handle %d events", nev, nerr);
    }

    return nerr;
}

int vhd_add_event(int fd, struct vhd_event_ctx* ctx)
{
    VHD_VERIFY(ctx && ctx->ops);

    struct epoll_event ev;
    ev.events = VHD_EPOLL_EVENTS;
    ev.data.ptr = ctx;
    if (epoll_ctl(g_event_loop_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        VHD_LOG_ERROR("Can't add event: %d", errno);
        return errno;
    }

    return 0;
}

void vhd_clear_eventfd(int fd)
{
    eventfd_read(fd, NULL);
}

void vhd_set_eventfd(int fd)
{
    eventfd_write(fd, 1);
}

int vhd_del_event(int fd)
{
    if (epoll_ctl(g_event_loop_fd, EPOLL_CTL_DEL, fd, NULL) == -1) {
        VHD_LOG_ERROR("Can't delete event: %d", errno);
        return errno;
    }

    return 0;
}
