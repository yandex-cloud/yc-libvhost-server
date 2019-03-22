#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "vhost-server/platform.h"
#include "vhost-server/virt_queue.h"

////////////////////////////////////////////////////////////////////////////////

/**
 * Holds private virtq data together with iovs we show users
 */
struct virtq_iov_private
{
    /* Private virtq fields */
    uint16_t used_head;
    uint16_t used_len;

    /* Iov we show to caller */
    struct virtio_iov iov;
};

static struct virtq_iov_private* alloc_iov(uint16_t nvecs)
{
    size_t size = sizeof(struct virtq_iov_private) + sizeof(struct virtq_iovec) * nvecs;

    struct virtq_iov_private* priv = vhd_alloc(size);
    priv->iov.nvecs = nvecs;
    return priv;
}

static void free_iov(struct virtq_iov_private* iov)
{
    if (iov) {
        vhd_free(iov);
    }
}

static int add_buffer(struct virtio_virtq* vq, void* addr, size_t len)
{
    if (vq->next_buffer == vq->qsz) {
        return -ENOSPC;
    }

    vq->buffers[vq->next_buffer] = (struct virtq_iovec) {addr, len};
    vq->next_buffer++;
    return 0;
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
    vq->broken = false;
    vq->buffers = vhd_calloc(qsz, sizeof(vq->buffers[0]));
    vq->next_buffer = 0;

    return 0;
}

void virtio_virtq_release(struct virtio_virtq* vq)
{
    if (vq) {
        vhd_free(vq->buffers);
    }
}

bool virtq_is_broken(struct virtio_virtq* vq)
{
    VHD_VERIFY(vq);
    return vq->broken;
}

static void mark_broken(struct virtio_virtq* vq)
{
    vq->broken = true;
}

static int walk_indirect_table(struct virtio_virtq* vq, const struct virtq_desc* table_desc)
{
    int res;
    struct virtq_desc desc;

    /* TODO: we need to validate that descriptor table memory, addressed by table_desc,
     * is a valid mapping for this device/guest. */

    if (table_desc->len == 0 || table_desc->len % sizeof(desc)) {
        VHD_LOG_ERROR("Bad indirect descriptor table length %d", table_desc->len);
        return -EINVAL;
    }

    int max_indirect_descs = table_desc->len / sizeof(desc); 
    int chain_len = 0;
    struct virtq_desc* pdesc = (struct virtq_desc*)(uintptr_t)table_desc->addr;
    struct virtq_desc* pdesc_first = pdesc;
    struct virtq_desc* pdesc_last = pdesc + max_indirect_descs - 1;

    do {
        /* Descriptor should point inside indirect table */
        if (pdesc < pdesc_first || pdesc > pdesc_last) {
            VHD_LOG_ERROR("Indirect descriptor %p is out of table bounds", pdesc);
            return -EINVAL;
        }

        memcpy(&desc, pdesc, sizeof(desc));

        /* 2.4.5.3.1: "The driver MUST NOT set the VIRTQ_DESC_F_INDIRECT flag within an indirect descriptor" */
        if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
            return -EINVAL;
        }

        /* 2.4.5.3.1: "A driver MUST NOT create a descriptor chain longer than the Queue Size of the device"
         * Indirect descriptors are part of the chain and should abide by this requirement */
        res = add_buffer(vq, (void*)(uintptr_t)desc.addr, desc.len);
        if (res != 0) {
            VHD_LOG_ERROR("Descriptor loop found, vring is broken");
            return -EINVAL;
        }

        /* Indirect descriptors are still chained by next pointer */
        pdesc = pdesc_first + pdesc->next;
        ++chain_len;

    } while (desc.flags & VIRTQ_DESC_F_NEXT);

    /* Looks like it is valid when chain len is not equal to table size, but it looks iffy. */
    if (chain_len != max_indirect_descs) {
        VHD_LOG_INFO("Indirect chain length %d is not equal to table size %d, which looks strange",
                chain_len, max_indirect_descs);
    }

    return 0;
}

static void dump_desc(const struct virtq_desc* desc, int idx)
{
    VHD_LOG_DEBUG("%d: addr = 0x%llx, len = %d\n",
                  idx, (unsigned long long) desc->addr, desc->len);
}

int virtq_dequeue_many(struct virtio_virtq* vq, virtq_handle_buffers_cb handle_buffers_cb, void* arg)
{
    int res;

    if (virtq_is_broken(vq)) {
        VHD_LOG_ERROR("virtqueue is broken, cannot process");
        return -ENODEV;
    }

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
        uint16_t descnum;
        uint16_t chain_len = 0;
        struct virtq_desc desc;

        /* Reset stored vectors position */
        vq->next_buffer = 0;

        /* Grab next descriptor head */
        head = vq->avail->ring[vq->last_avail % vq->qsz];
        descnum = head;
    
        /* Walk descriptor chain */
        do {
            /* Check that descriptor is in-bounds */
            if (descnum >= vq->qsz) {
                VHD_LOG_ERROR("Descriptor num %d is out-of-bounds", descnum);
                res = -EINVAL;
                goto queue_broken;
            }

            /* We explicitly make a local copy here to avoid any possible TOCTOU problems. */
            memcpy(&desc, vq->desc + descnum, sizeof(desc));
            dump_desc(&desc, descnum);

            if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
                /* 2.4.5.3.1: A driver MUST NOT set both VIRTQ_DESC_F_INDIRECT and VIRTQ_DESC_F_NEXT in flags */
                if (desc.flags & VIRTQ_DESC_F_NEXT) {
                    VHD_LOG_ERROR("Can't handle indirect descriptors and next flag");
                    res = -EINVAL;
                    goto queue_broken;
                }

                res = walk_indirect_table(vq, &desc);
                if (res != 0) {
                    goto queue_broken;
                }

                /* Descriptor chain should always terminate on indirect,
                 * which means we should not see NEXT flag anymore, and we have checked exactly that above.
                 * We document our assumption with an assert here. */
                VHD_ASSERT((desc.flags & VIRTQ_DESC_F_NEXT) == 0);

            } else {
                res = add_buffer(vq, (void*)(uintptr_t)desc.addr, desc.len);
                if (res != 0) {
                    /* We always reserve space beforehand, so this is a descriptor loop */
                    VHD_LOG_ERROR("Descriptor loop found, vring is broken");
                    res = -EINVAL;
                    goto queue_broken;
                }
            }

            /* next desc is not touched if loop terminated */
            descnum = desc.next;
            chain_len++;
        } while (desc.flags & VIRTQ_DESC_F_NEXT);

        /* Create iov copy from stored buffer for client handling */
        struct virtq_iov_private* priv = alloc_iov(vq->next_buffer);
        memcpy(priv->iov.buffers, vq->buffers, priv->iov.nvecs * sizeof(vq->buffers[0]));
        priv->used_head = head;
        priv->used_len = chain_len;

        /* Send this over to handler */
        handle_buffers_cb(arg, &priv->iov);
        vq->last_avail++;
    }

    /* TODO: restore notifier mask here */
    return 0;

queue_broken:
    mark_broken(vq);
    return res;
}

void virtq_commit_buffers(struct virtio_virtq* vq, struct virtio_iov* iov)
{
    VHD_VERIFY(vq);

    /* Put buffer head index and len into used ring */
    struct virtq_iov_private* priv = containerof(iov, struct virtq_iov_private, iov);
    struct virtq_used_elem* used = &vq->used->ring[vq->used->idx % vq->qsz];
    used->id = priv->used_head;
    used->len = priv->used_len;

    vhd_smp_wmb();
    vq->used->idx++;

    free_iov(priv);
}
