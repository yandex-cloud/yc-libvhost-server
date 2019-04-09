#pragma once

#include "vhost-server/event.h"
#include "vhost-server/intrusive_list.h"
#include "vhost-server/vhost_proto.h"
#include "vhost-server/virt_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_vdev;
struct vhd_vring;

/**
 * TODO: need a separate unit for this
 */
struct vhd_guest_memory_region
{
    /* Guest physical address */
    vhd_paddr_t gpa;

    /* Userspace virtual address, where this region is mapped in virtio backend on client */
    vhd_uaddr_t uva;

    /* Host virtual address, our local mapping */
    void* hva;

    /* Total guest physical pages this region contains */
    uint32_t pages;

    /* Shared mapping fd */
    int fd;
};

/**
 * TODO: need a separate unit for this
 */
struct vhd_guest_memory_map
{
    struct vhd_guest_memory_region regions[VHOST_USER_MEM_REGIONS_MAX];
};

enum vhd_vdev_state
{
    /* Device is initialized. For vhost-user server devices listening socket is created. */
    VDEV_INITIALIZED = 0,

    /* Device is in server mode and is listening for connection */
    VDEV_LISTENING,

    /* Device has a client connection and can start negotiating vhost-user handshake */
    VDEV_CONNECTED,
};

/**
 * Vhost device type description.
 */
struct vhd_vdev_type
{
    /* Human-readable description */
    const char* desc;

    /* Polymorphic type ops */
    uint64_t (*get_features)(struct vhd_vdev* vdev);
    int (*set_features)(struct vhd_vdev* vdev, uint64_t features);
    size_t (*get_config)(struct vhd_vdev* vdev, void* cfgbuf, size_t bufsize);
};

/**
 * Vhost generic device instance.
 *
 * Describes a single virtual device backend that we serve.
 * Each vdev can be either a vhost server or client (TODO).
 *
 * Devices are polymorphic through their respective types.
 */
struct vhd_vdev
{
    /* Device type description */
    const struct vhd_vdev_type* type;

    /* Server socket fd when device is a vhost-user server */
    int listenfd;

    /* Connected device fd. Single active connection per device. */
    int connfd;

    /* Handles both server and conn event (since only one can exist at a time) */
    struct vhd_event_ctx sock_ev;

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
    uint64_t supported_device_features;
    uint64_t negotiated_device_features;

    /** Maximum amount of request queues this device can support */
    uint32_t max_queues; /* Set by device backend as a limit of what we can support*/
    uint32_t num_queues; /* Set by client during negotiation, guaranteed to be <= max_queues */
    struct vhd_vring* vrings; /* Total num_queues elements */

    /**
     * Memory mappings that relate to this device 
     * TODO: it is wrong to have separate mappings per device, they should really be per-guest
     */
    struct vhd_guest_memory_map guest_memmap;

    /** Global vdev list */
    LIST_ENTRY(vhd_vdev) vdev_list;
};

/**
 * Init new generic vhost device in server mode
 * @socket_path     Listen socket path
 * @type            Device type description
 * @vdev            vdev instance to initialize
 * @max_queues      Maximum number of queues this device can support
 */
int vhd_vdev_init_server(struct vhd_vdev* vdev, const char* socket_path, const struct vhd_vdev_type* type, int max_queues);

/**
 * Destroy vdev instance
 */
void vhd_vdev_uninit(struct vhd_vdev* vdev);

static inline uint64_t vhd_vdev_get_features(struct vhd_vdev* vdev)
{
    VHD_ASSERT(vdev && vdev->type);
    return vdev->type->get_features(vdev);
}

static inline int vhd_vdev_set_features(struct vhd_vdev* vdev, uint64_t features)
{
    VHD_ASSERT(vdev && vdev->type);
    return vdev->type->set_features(vdev, features);
}

static inline size_t vhd_vdev_get_config(struct vhd_vdev* vdev, void* cfgbuf, size_t bufsize)
{
    VHD_ASSERT(vdev);
    return vdev->type->get_config(vdev, cfgbuf, bufsize);
}

/**
 * Device vring instance
 */
struct vhd_vring
{
    /* owning vdev */
    struct vhd_vdev* vdev;

    /* This structure is used to collect info about client vring during
     * several vhost packets until we have enought to initialize it */
    struct vring_client_info {
        void* desc_addr;
        void* avail_addr;
        void* used_addr;
        int num;
        int base;
    } client_info;

    /* vring id, acts as an index in its owning device */
    int id;

    /* client-supplied eventfds */
    int kickfd;
    int callfd;
    int errfd;

    /* vring can service requests */
    bool is_enabled;

    /* Client kick event */
    struct vhd_event_ctx kickev;

    /* Low-level virtio queue */
    struct virtio_virtq vq;
};

/**
 * Initialize vring
 * @vring       vring instance
 * @id          vring id
 * @vdev        vring owning device instance
 */
void vhd_vring_init(struct vhd_vring* vring, int id, struct vhd_vdev* vdev);

#ifdef __cplusplus
}
#endif
