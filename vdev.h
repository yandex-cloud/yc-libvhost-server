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

struct vhd_memory_map;
struct vhd_memory_log;
struct vhd_work;

/**
 * Vhost generic device instance.
 *
 * Devices are polymorphic through their respective types.
 */
struct vhd_vdev {
    char *log_tag;

    /* Accosiated client private data */
    void *priv;

    /* Device type description */
    const struct vhd_vdev_type *type;

    /* Server socket fd when device is a vhost-user server */
    int listenfd;
    struct vhd_io_handler *listen_handler;

    /* Connected device fd. Single active connection per device. */
    int connfd;
    struct vhd_io_handler *conn_handler;

    /* Attached request queue */
    struct vhd_request_queue *rq;

    /*
     * Vhost protocol features which can be supported for this vdev and
     * those which have been actually enabled during negotiation.
     */
    uint64_t supported_protocol_features;
    uint64_t negotiated_protocol_features;
    uint64_t supported_features;
    uint64_t negotiated_features;

    /* Maximum amount of request queues this device can support */
    uint16_t num_queues;
    struct vhd_vring *vrings; /* Total num_queues elements */

    /* Gets called after mapping guest memory region */
    int (*map_cb)(void *addr, size_t len, void *priv);

    /* Gets called before unmapping guest memory region */
    int (*unmap_cb)(void *addr, size_t len, void *priv);

    struct vhd_memory_map *memmap;
    struct vhd_memory_map *old_memmap;
    struct vhd_memory_log *memlog;
    struct vhd_memory_log *old_memlog;

    /**
     * Shared memory to store information about inflight requests and restore
     * virtqueue state after reconnect.
     */
    struct inflight_split_region *inflight_mem;
    uint64_t inflight_size;

    /* #vrings which may have requests in flight */
    uint16_t num_vrings_in_flight;
    /* #vrings started and haven't yet acknowledged stop */
    uint16_t num_vrings_started;

    /* callback and arg to be called when the device is released */
    void (*release_cb)(void *);
    void *release_arg;

    /** Global vdev list */
    LIST_ENTRY(vhd_vdev) vdev_list;

    /* #vrings performing an action in response to a control message */
    uint16_t num_vrings_handling_msg;
    /* function to call once the current message is handled in all vrings */
    int (*handle_complete)(struct vhd_vdev *vdev);

    /* whether an ACK should be sent once the message is handled  */
    bool ack_pending;

    /* fd to keep open until handle_complete and to close there */
    int keep_fd;

    struct vhd_work *work;
};

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
 * Stop vhost device.  Once this returns no more new requests will reach the
 * backend.  @release_cb(@release_arg) will be called once all requests are
 * completed and the associated resources released.
 */
int vhd_vdev_stop_server(struct vhd_vdev *vdev,
                         void (*release_cb)(void *), void *release_arg);

/**
 * Device vring instance
 */
struct vhd_vring {
    struct vhd_vdev *vdev;
    char *log_tag;

    int kickfd;
    int callfd;
    int errfd;

    /* started as seen from control plane */
    bool started_in_ctl;
    /* requested to disconnect */
    bool disconnecting;

    /* Client kick event */
    struct vhd_io_handler *kick_handler;

    /* called in control plane once vring is drained */
    int (*on_drain_cb)(struct vhd_vring *);

   /*
    * ring addresses cache
    * used to update actual ring addresses when mapping is changed
    */
    struct {
        uint64_t avail;
        uint64_t desc;
        uint64_t used;
    } addr_cache;

    /*
     * vq attributes that may change while vring is started; these are updated
     * in the control event loop and propagated via BH into vq
     */
    struct {
        uint32_t flags;
        void *desc;
        void *avail;
        void *used;
        struct vhd_memory_map *mm;
        struct vhd_memory_log *log;
    } shadow_vq;

    /*
     * the fields below are only accessed in dataplane unless the vring is
     * known to be stopped
     */
    struct virtio_virtq vq;
    /* started as seen from dataplane */
    bool started_in_rq;
    /* #requests pending completion */
    uint16_t num_in_flight;
};

void vhd_vring_inc_in_flight(struct vhd_vring *vring);
void vhd_vring_dec_in_flight(struct vhd_vring *vring);

#ifdef __cplusplus
}
#endif
