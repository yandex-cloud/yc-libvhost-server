#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "vhost-server/platform.h"
#include "vhost-server/virt_queue.h"

////////////////////////////////////////////////////////////////////////////////

/*
 * TODO: this screams for a simple chunk-based allocator
 */

static void sglist_alloc(struct virtq_sglist* sgl, size_t reserve)
{
    sgl->ncap = reserve;
    sgl->nvecs = 0;
    sgl->nbytes = 0;
    sgl->iovecs = vhd_calloc(sizeof(*(sgl->iovecs)), reserve);
}

static void sglist_reserve(struct virtq_sglist* sgl, size_t reserve_by)
{
    VHD_ASSERT(sgl->ncap >= sgl->nvecs);
    size_t remaining_cap = sgl->ncap - sgl->nvecs;
    if (remaining_cap >= reserve_by) {
        return;
    }

    size_t added_cap = reserve_by - remaining_cap;
    struct virtq_iovec* iovecs = vhd_calloc(sizeof(*iovecs), sgl->ncap + added_cap);
    memcpy(iovecs, sgl->iovecs, sgl->ncap);
    vhd_free(sgl->iovecs);
    sgl->ncap += added_cap;
    sgl->iovecs = iovecs;
}

static int sglist_add_buffer(struct virtq_sglist* sgl, void* addr, size_t len)
{
    if (sgl->ncap == sgl->nvecs) {
        return -ENOSPC;
    }

    sgl->iovecs[sgl->nvecs] = (struct virtq_iovec) {addr, len};
    sgl->nbytes += len;
    sgl->nvecs++;
    return 0;
}

static void sglist_reset(struct virtq_sglist* sgl)
{
    sgl->ncap = 0;
    sgl->nvecs = 0;
    sgl->nbytes = 0;
    vhd_free(sgl->iovecs);
}

int virtio_virtq_attach(struct virtio_virtq* vq,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        int qsz,
                        int avail_base)
{
    VHD_VERIFY(vq);
    VHD_VERIFY(desc_addr);
    VHD_VERIFY(used_addr);
    VHD_VERIFY(avail_addr);

    /* Client explicitly told us where to look for stuff, so no sanity checks.
     * Assume that vhost initiation already verified memory layout */
    vq->desc = desc_addr;
    vq->used = used_addr;
    vq->avail = avail_addr;
    vq->qsz = qsz;
    vq->last_avail = avail_base;
    return 0;
}

static int walk_indirect_table(struct virtio_virtq* vq, struct virtq_sglist* sglist, const struct virtq_desc* table_desc)
{
    int res;
    struct virtq_desc desc;

    /* TODO: we need to validate that descriptor table memory, addressed by table_desc,
     * is a valid mapping for this device/guest. */

    if (table_desc->len == 0 || table_desc->len % sizeof(desc)) {
        return -EINVAL;
    }

    int max_indirect_descs = table_desc->len / sizeof(desc); 
    struct virtq_desc* pdesc = (struct virtq_desc*)(uintptr_t)table_desc->addr;
    struct virtq_desc* pdesc_first = pdesc;
    struct virtq_desc* pdesc_last = pdesc + max_indirect_descs - 1;

    /* 2.4.5.3.1: A driver MUST NOT create a descriptor chain longer than the Queue Size of the device
     * Indirect descriptors, if multiple, should create a chain that should follow this requirement */
    sglist_reserve(sglist, MIN(max_indirect_descs, vq->qsz));

    do {
        /* Descriptor should point inside indirect table */
        if (pdesc < pdesc_first || pdesc > pdesc_last) {
            VHD_LOG_ERROR("Indirect descriptor %p is out of table bounds", pdesc);
            return -EINVAL;
        }

        memcpy(&desc, pdesc, sizeof(desc));

        /* 2.4.5.3.1: The driver MUST NOT set the VIRTQ_DESC_F_INDIRECT flag within an indirect descriptor */
        if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
            return -EINVAL;
        }

        res = sglist_add_buffer(sglist, (void*)(uintptr_t)desc.addr, desc.len);
        if (res != 0) {
            /* We always reserve space beforehand, so this is a descriptor loop */
            VHD_LOG_ERROR("Descriptor loop found, vring is broken");
            return -EINVAL;
        }

        /* Indirect descriptors are still chained by next pointer */
        pdesc = pdesc_first + pdesc->next;

    } while (desc.flags & VIRTQ_DESC_F_NEXT);

    return 0;
}

static void dump_desc(const struct virtq_desc* desc, int idx)
{
    VHD_LOG_DEBUG("%d: addr = 0x%llx, len = %d\n",
                  idx, (unsigned long long) desc->addr, desc->len);
}

static void pop_last_avail(struct virtio_virtq* vq, uint32_t len)
{
    struct virtq_used_elem* used = &vq->used->ring[vq->used->idx % vq->qsz];

    /* Put buffer head index and len into used ring */
    used->id = vq->avail->ring[vq->last_avail % vq->qsz];
    used->len = len;

    vhd_smp_wmb();
    vq->used->idx++;

    vq->last_avail++;
}

int virtq_dequeue_many(struct virtio_virtq* vq, virtq_handle_buffers_cb handle_buffers_cb, void* arg)
{
    int res;

    /* Limit this run to initial number of advertised descriptors.
     * TODO: limit it better in client */
    uint16_t num_avail = vq->avail->idx - vq->last_avail;
    if (!num_avail) {
        return 0;
    }

    /* Make sure that further desc reads do not pass avail->idx read.
     * Not nessesary on x86_64, which is why rmb is really defined as a compiler barrier. */
    vhd_smp_rmb();

    /* TODO: disable extra notifies from this point */

    for (uint16_t i = 0; i < num_avail; ++i) {
        uint16_t head;
        struct virtq_desc desc;
        struct virtq_sglist sglist;
        uint32_t chain_len = 0;

        /* 2.4.5.3.1: A driver MUST NOT create a descriptor chain longer than the Queue Size of the device
         * Thus initial sglist size is enough if there are no indirect descriptors.
         * If there are indirect descriptors, we will expand. */
        sglist_alloc(&sglist, vq->qsz);

        /* Grab next descriptor head */
        head = vq->avail->ring[vq->last_avail % vq->qsz];
    
        /* Walk descriptor chain */
        do {
            /* Copy first descriptor at head.
             * We explicitly make a local copy here to avoid any possible TOCTOU problems. */
            memcpy(&desc, vq->desc + head, sizeof(desc));
            dump_desc(&desc, head);

            if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
                /* 2.4.5.3.1: A driver MUST NOT set both VIRTQ_DESC_F_INDIRECT and VIRTQ_DESC_F_NEXT in flags */
                if (desc.flags & VIRTQ_DESC_F_NEXT) {
                    VHD_LOG_ERROR("Can't handle indirect descriptors and next flag");
                    return -EINVAL;
                }

                res = walk_indirect_table(vq, &sglist, &desc);
                if (res != 0) {
                    return res;
                }

            } else {
                res = sglist_add_buffer(&sglist, (void*)(uintptr_t)desc.addr, desc.len);
                if (res != 0) {
                    /* We always reserve space beforehand, so this is a descriptor loop */
                    VHD_LOG_ERROR("Descriptor loop found, vring is broken");
                    /* TODO: mark ring as broken */
                    return -EINVAL;
                }
            }

            /* next head is not touched if loop terminated */
            head = desc.next;
            chain_len++;
        } while (desc.flags & VIRTQ_DESC_F_NEXT);

        /* Send this over to handler */
        handle_buffers_cb(arg, &sglist);

        /* Cleanup sglist and put buffer in used */
        sglist_reset(&sglist);
        pop_last_avail(vq, chain_len);
    }

    /* TODO: restore notifier mask here */
    return 0;
}
