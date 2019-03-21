#pragma once

#include "vhost-server/platform.h"
#include "vhost-server/virtio10.h"

#ifdef __cplusplus
extern "C" {
#endif

struct virtq_iovec {
    void* start;
    size_t len;
};
   
struct virtq_sglist
{
    size_t ncap;    /* Capacity in iovecs */
    size_t nvecs;   /* Total vectors */
    size_t nbytes;  /* Total bytes stored in sglist */
    struct virtq_iovec* iovecs;
};

struct virtio_virtq
{
    struct virtq_desc* desc;
    struct virtq_avail* avail;
    struct virtq_used* used;

    /* Size of raw mapped queue area in bytes */
    size_t mapped_size;

    /* Size of queue in number of descriptors it can hold */
    int qsz;

    /* Shadow avail ring index */
    int last_avail;

    /* 2.4.5.3.1: A driver MUST NOT create a descriptor chain longer than the Queue Size of the device
     * Thus initial sglist size must be enough to hold a valid descriptor chain */
    struct virtq_sglist sglist;

    /* Virtqueue is broken, probably because there is an invalid descriptor chain in it.
     * Broken status is sticky and so far cannot be repared. */
    bool broken;
};

int virtio_virtq_attach(struct virtio_virtq* vq,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        int qsz,
                        int avail_base);

void virtio_virtq_release(struct virtio_virtq* vq);

bool virtq_is_broken(struct virtio_virtq* vq);

typedef void(*virtq_handle_buffers_cb)(void* arg, const struct virtq_sglist* buffers);
int virtq_dequeue_many(struct virtio_virtq* vq, virtq_handle_buffers_cb handle_buffers_cb, void* arg);

#ifdef __cplusplus
}
#endif
