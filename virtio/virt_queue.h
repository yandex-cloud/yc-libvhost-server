#pragma once

#include <vhost/platform.h>
#include <vhost/types.h>

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
    struct vhd_buffer buffers[0 /*nvecs*/];
};

/*
 * Memory mapping context
 * Implemented by client to validate and map guest memory addresses
 */
struct virtio_mm_ctx;

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
void* virtio_map_guest_phys_range(struct virtio_mm_ctx* mm, uint64_t gpa, uint32_t len);

struct virtio_virtq
{
    struct virtq_desc* desc;
    struct virtq_avail* avail;
    struct virtq_used* used;

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
};

int virtio_virtq_attach(struct virtio_virtq* vq,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        int qsz,
                        int avail_base);

void virtio_virtq_release(struct virtio_virtq* vq);

bool virtq_is_broken(struct virtio_virtq* vq);

typedef void(*virtq_handle_buffers_cb)(void* arg, struct virtio_virtq* vq, struct virtio_iov* iov);
int virtq_dequeue_many(struct virtio_virtq* vq,
                       struct virtio_mm_ctx* mm_ctx,
                       virtq_handle_buffers_cb handle_buffers_cb,
                       void* arg);

void virtq_commit_buffers(struct virtio_virtq* vq, struct virtio_iov* iov);

void virtq_notify(struct virtio_virtq* vq);

void virtq_set_notify_fd(struct virtio_virtq* vq, int fd);

#ifdef __cplusplus
}
#endif
