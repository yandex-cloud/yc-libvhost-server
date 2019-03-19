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

    /* We're not working with a single vring concurrently.
     * While this is true we can preallocate @size number of iovectors
     * and reuse them to process descriptor chains */
    //struct virtq_sglist sglist;
};

int virtio_virtq_attach(struct virtio_virtq* vq,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        int qsz,
                        int avail_base);

typedef void(*virtq_handle_buffers_cb)(void* arg, const struct virtq_sglist* buffers);
int virtq_dequeue_many(struct virtio_virtq* vq, virtq_handle_buffers_cb handle_buffers_cb, void* arg);

#ifdef __cplusplus
}
#endif
