#include <pthread.h>

#include "vhost-server/server.h"
#include "vhost-server/intrusive_list.h"
#include "vhost-server/event.h"
#include "vhost-server/vdev.h"

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
    while (!vhd_event_loop_terminated(g_vhost_evloop)) {
        int res = vhd_run_event_loop(g_vhost_evloop, -1);
        if (res < 0) {
            VHD_LOG_ERROR("vhost event loop iteration failed: %d", res);
            break;
        }
    }
    
    free_vhost_event_loop();
    return NULL;
}

int vhd_start_vhost_server(void)
{
    if (g_vhost_evloop != NULL) {
        return 0;
    }

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
