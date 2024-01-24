#pragma once

#include "event.h"
#include "queue.h"

#include "virtio/virt_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_vdev;
struct vhd_vring;
struct vhd_request_queue;

enum vhd_vdev_state {
    /*
     * Device is initialized. For vhost-user server devices listening socket is
     * created.
     */
    VDEV_INITIALIZED = 0,

    /* Device is in server mode and is listening for connection */
    VDEV_LISTENING,

    /*
     * Device has a client connection and can start negotiating vhost-user
     * handshake
     */
    VDEV_CONNECTED,

    /*
     * Device is being unregistered
     */
    VDEV_TERMINATING,
};

/**
 * Vhost device type description.
 */
struct vhd_vdev_type {
    /* Human-readable description */
    const char *desc;

    /* Polymorphic type ops */
    uint64_t (*get_features)(struct vhd_vdev *vdev);
    int (*set_features)(struct vhd_vdev *vdev, uint64_t features);
    size_t (*get_config)(struct vhd_vdev *vdev, void *cfgbuf,
                         size_t bufsize, size_t offset);
    int (*dispatch_requests)(struct vhd_vdev *vdev, struct vhd_vring *vring,
                             struct vhd_request_queue *rq);
    void (*free)(struct vhd_vdev *vdev);
};

struct vhd_work;

/**
 * Vhost generic device instance.
 *
 * Describes a single virtual device backend that we serve.
 * Each vdev can be either a vhost server or client (TODO).
 *
 * Devices are polymorphic through their respective types.
 */
typedef uint64_t vhd_paddr_t;

struct vhd_vdev {
    /* Accosiated client private data */
    void *priv;

    /* Device type description */
    const struct vhd_vdev_type *type;

    /* Server socket fd when device is a vhost-user server */
    int listenfd;

    /* Connected device fd. Single active connection per device. */
    int connfd;

    /*
     * Handles both server and conn event (since only one can exist at a time)
     */
    struct vhd_event_ctx sock_ev;

    /* Attached request queue */
    struct vhd_request_queue *rq;

    /* Current state */
    enum vhd_vdev_state state;

    /* Device has a client owner */
    bool is_owned;

    /*
     * Vhost protocol features which can be supported for this vdev and
     * those which have been actually enabled during negotiation.
     */
    uint64_t supported_protocol_features;
    uint64_t negotiated_protocol_features;
    uint64_t supported_features;
    uint64_t negotiated_features;

    /** Maximum amount of request queues this device can support */
    /* Set by device backend as a limit of what we can support*/
    uint32_t max_queues;
    /* Set by client during negotiation, guaranteed to be <= max_queues */
    uint32_t num_queues;
    struct vhd_vring *vrings; /* Total num_queues elements */

    /**
     * Memory mappings that relate to this device
     * TODO: it is wrong to have separate mappings per device, they should
     * really be per-guest
     */
    struct vhd_guest_memory_map *guest_memmap;

    /* Gets called after mapping guest memory region */
    int (*map_cb)(void *addr, size_t len, void *priv);

    /* Gets called before unmapping guest memory region */
    int (*unmap_cb)(void *addr, size_t len, void *priv);

    /**
     * Shared memory to store information about inflight requests and restore
     * virtqueue state after reconnect.
     */
    struct inflight_split_region *inflight_mem;
    uint64_t inflight_size;

    /**
     * Refcount and callback for device stopping
     */
    atomic_uint refcount;
    void (*unregister_cb)(void *);
    void *unregister_arg;

    /** Global vdev list */
    LIST_ENTRY(vhd_vdev) vdev_list;

    struct vhd_work *work;
};

/**
 * Create and run default vhost event loop.
 *
 * vhost event loop will run in a separate low-priority thread.
 * Should be called before any device is registered.
 */
int vhd_start_vhost_event_loop(void);

/**
 * Terminate vhost event loop.
 *
 * Any and all vhost requests will not be services after this.
 */
void vhd_stop_vhost_event_loop(void);

/**
 * Init new generic vhost device in server mode
 * @socket_path     Listen socket path
 * @type            Device type description
 * @vdev            vdev instance to initialize
 * @max_queues      Maximum number of queues this device can support
 * @rq              Associated request queue
 * @priv            User private data
 * @map_cb          User function to call after mapping guest memory
 * @unmap_cb        User function to call before unmapping guest memory
 */
int vhd_vdev_init_server(
    struct vhd_vdev *vdev,
    const char *socket_path,
    const struct vhd_vdev_type *type,
    int max_queues,
    struct vhd_request_queue *rq,
    void *priv,
    int (*map_cb)(void *addr, size_t len, void *priv),
    int (*unmap_cb)(void *addr, size_t len, void *priv));

/**
 * Stop vhost device
 */
int vhd_vdev_stop_server(struct vhd_vdev *vdev,
                         void (*unregister_complete)(void *), void *arg);

static inline uint64_t vhd_vdev_get_features(struct vhd_vdev *vdev)
{
    VHD_ASSERT(vdev && vdev->type && vdev->type->get_features);
    return vdev->type->get_features(vdev);
}

static inline int vhd_vdev_set_features(struct vhd_vdev *vdev,
                                        uint64_t features)
{
    VHD_ASSERT(vdev && vdev->type && vdev->type->set_features);
    return vdev->type->set_features(vdev, features);
}

static inline size_t vhd_vdev_get_config(struct vhd_vdev *vdev, void *cfgbuf,
                                         size_t bufsize, size_t offset)
{
    VHD_ASSERT(vdev && vdev->type && vdev->type->get_config);
    return vdev->type->get_config(vdev, cfgbuf, bufsize, offset);
}

static inline int vhd_vdev_dispatch_requests(struct vhd_vdev *vdev,
                                             struct vhd_vring *vring)
{
    VHD_ASSERT(vdev && vdev->type && vdev->type->dispatch_requests);
    return vdev->type->dispatch_requests(vdev, vring, vdev->rq);
}

static inline
struct vhd_guest_memory_map *vhd_vdev_mm_ctx(struct vhd_vdev *vdev)
{
    VHD_ASSERT(vdev);
    return vdev->guest_memmap;
}

void vhd_gpa_range_mark_dirty(struct vhd_guest_memory_map *mm, vhd_paddr_t gpa,
                              size_t len);
void vhd_hva_range_mark_dirty(struct vhd_guest_memory_map *mm, void *hva,
                              size_t len);
bool vhd_logging_started(struct virtio_virtq *vq);

/**
 * Device vring instance
 */
struct vhd_vring {
    /* owning vdev */
    struct vhd_vdev *vdev;

    /*
     * This structure is used to collect info about client vring during
     * several vhost packets until we have enought to initialize it
     */
    struct vring_client_info {
        uint32_t flags;
        void *desc_addr;
        void *avail_addr;
        void *used_addr;
        int num;
        int base;
        void *inflight_addr;
        vhd_paddr_t used_gpa_base;
    } client_info;

    /* vring id, acts as an index in its owning device */
    int id;

    /* client-supplied eventfds */
    int kickfd;
    int callfd;
    int errfd;

    /* vring can service master's requests */
    bool is_started;

    /* Client kick event */
    struct vhd_event_ctx kickev;

    /* Low-level virtio queue */
    struct virtio_virtq vq;

    /*
     * Is called when vring is drained.
     */
    int (*on_drain_cb)(struct vhd_vring *);

   /*
    * refcount for in-flight requests per vring
    * not atomic - is supposed to be accessed from vdev's request queue (bh)
    */
    uint64_t refcount;
};

void vhd_vring_ref(struct vhd_vring *vring);
void vhd_vring_unref(struct vhd_vring *vring);

/**
 * Initialize vring
 * @vring       vring instance
 * @id          vring id
 * @vdev        vring owning device instance
 */
void vhd_vring_init(struct vhd_vring *vring, int id, struct vhd_vdev *vdev);

/**
 * Stop vring
 */
void vhd_vring_stop(struct vhd_vring *vring);

void vhd_memmap_ref(struct vhd_guest_memory_map *mm);
void vhd_memmap_unref(struct vhd_guest_memory_map *mm);

#ifdef __cplusplus
}
#endif
