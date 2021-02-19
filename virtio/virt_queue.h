#pragma once

#include <pthread.h>

#include "vhost/types.h"
#include "vhost_spec.h"

#include "virtio_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Describes parsed buffer chain to be handled by virtio device type
 */
struct virtio_iov
{
    uint16_t nvecs;
    struct vhd_buffer buffers[/*nvecs*/];
};

/*
 * Memory mapping context
 * Implemented by client to validate and map guest memory addresses
 */
struct vhd_guest_memory_map;

/**
 * Given a guest physical memory region produce its VA mapping on the host.
 * This function is a linker dependancy for virtio code
 *
 * @mm      Client memory management context
 * @gpa     Guest physical address
 * @len     Total bytes in physical range
 *
 * @return  mapped host VA or NULL in case of error
 */
void *virtio_map_guest_phys_range(struct vhd_guest_memory_map *mm,
                                  uint64_t gpa, uint32_t len);

struct virtio_virtq
{
    uint32_t flags;
    struct virtq_desc* desc;
    struct virtq_avail* avail;
    struct virtq_used* used;
    uint64_t used_gpa_base;

    /* Size of queue in number of descriptors it can hold */
    int qsz;

    /* Shadow avail ring index */
    int last_avail;

    /* 2.4.5.3.1: A driver MUST NOT create a descriptor chain longer than the Queue Size of the device
     * Thus we can have a known number of preallocated buffers to hold a valid descriptor chain */
    uint16_t next_buffer;           /* Total preallocated buffers used */
    struct vhd_buffer* buffers;     /* qsz preallocated buffers */

    /* Virtqueue is broken, probably because there is an invalid descriptor chain in it.
     * Broken status is sticky and so far cannot be repared. */
    bool broken;

    /* eventfd for used buffers notification.
     * can be reset after virtq is started. */
    int notify_fd;

    /* inflight information */
    uint64_t req_cnt;
    struct inflight_split_region *inflight_region;
    bool inflight_check;

    /* Usage statistics */
    struct vq_stat {
        /* Metrics provided to users */
        struct vhd_vq_metrics metrics;

        /* Metrics service info fields. Not provided to uses */
        /* timestamps for periodic metrics */
        time_t period_start_ts;
    } stat;
};

int virtio_virtq_attach(struct virtio_virtq* vq,
                        uint32_t flags,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        uint64_t used_gpa_base,
                        int qsz,
                        int avail_base,
                        void* inflight_addr);

void virtio_virtq_release(struct virtio_virtq* vq);

bool virtq_is_broken(struct virtio_virtq* vq);

typedef void(*virtq_handle_buffers_cb)(void* arg, struct virtio_virtq* vq, struct virtio_iov* iov);
int virtq_dequeue_many(struct virtio_virtq *vq,
                       struct vhd_guest_memory_map *mm,
                       virtq_handle_buffers_cb handle_buffers_cb,
                       void *arg);

void virtq_commit_buffers(struct virtio_virtq* vq, struct virtio_iov* iov);

void virtq_notify(struct virtio_virtq* vq);

void virtq_set_notify_fd(struct virtio_virtq* vq, int fd);

void virtio_free_iov(struct virtio_iov *iov);
uint16_t virtio_iov_get_head(struct virtio_iov *iov);

void virtio_virtq_get_stat(struct virtio_virtq *vq,
                           struct vhd_vq_metrics *metrics);

#ifdef __cplusplus
}
#endif
