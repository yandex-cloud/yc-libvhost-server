#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/eventfd.h>

#include <vhost/platform.h>
#include "virt_queue.h"

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

static int virtq_dequeue_one(struct virtio_virtq* vq,
        struct virtio_mm_ctx* mm, uint16_t head,
        virtq_handle_buffers_cb handle_buffers_cb, void* arg);

static struct virtq_iov_private* alloc_iov(uint16_t nvecs)
{
    size_t size = sizeof(struct virtq_iov_private) + sizeof(struct vhd_buffer) * nvecs;

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

static int add_buffer(struct virtio_virtq* vq, void* addr, size_t len, bool write_only)
{
    if (vq->next_buffer == vq->qsz) {
        return -ENOSPC;
    }

    vq->buffers[vq->next_buffer] = (struct vhd_buffer) {
        .base = addr,
        .len = len,
        .write_only = write_only,
    };

    vq->next_buffer++;
    return 0;
}

static int map_buffer(struct virtio_virtq* vq, struct virtio_mm_ctx* mm, uint64_t gpa, size_t len, bool write_only)
{
    void* addr = virtio_map_guest_phys_range(mm, gpa, len);
    if (!addr) {
        return -EINVAL;
    }

    return add_buffer(vq, addr, len, write_only);
}

/* Modify inflight descriptor after dequeue request from the available
 * ring.
 */
static void virtq_inflight_avail_update(struct virtio_virtq* vq,
        uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    vq->inflight_region->desc[head].counter = vq->req_cnt;
    vq->req_cnt++;
    vq->inflight_region->desc[head].inflight = 1;
}

/* Prepare the inflight descriptor for commit. */
static void virtq_inflight_used_update(struct virtio_virtq* vq,
        uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    vq->inflight_region->desc[head].next = vq->inflight_region->last_batch_head;
    vq->inflight_region->last_batch_head = head;
}

/* Post commit inflight descriptor handling. */
static void virtq_inflight_used_commit(struct virtio_virtq* vq,
        uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    vq->inflight_region->desc[head].inflight = 0;
    vhd_smp_wmb();
    vq->inflight_region->used_idx = vq->used->idx;
}

/* If the value of ``used_idx`` does not match the ``idx`` value of
 * used ring (means the inflight field of ``inflight_split_desc``
 * entries in last batch may be incorrect).
 */
static void virtq_inflight_reconnect_update(struct virtio_virtq* vq)
{
    int batch_size;
    uint16_t idx;

    vq->req_cnt = 0;
    if (!vq->inflight_region) {
        return;
    }

    /* Initialize the global req counter for the inflight descriptors. */
    for (idx = 0; idx < vq->inflight_region->desc_num; idx++) {
        if (vq->inflight_region->desc[idx].counter > vq->req_cnt) {
            vq->req_cnt = vq->inflight_region->desc[idx].counter;
        }
    }
    vq->req_cnt++;

    batch_size = vq->used->idx - vq->inflight_region->used_idx;
    if (!batch_size) {
        /* Last batch was sent successfully. Nothing to update. */
        return;
    }

    /* TODO: We should send a notify when the notify_fd will be
     * initialized since the last_batch commit was incomplete.
     * Disconnect happened before the notify event. There is
     * still a very small gap where the virtq_inflight_used_commit()
     * routine completed successfully and after it the daemon
     * stops and didn't send a notify. In this case the last_batch
     * will be in the correct state and no notify will be sent.
     * Need to simulate and investigate it more precisely.
     */
    vq->inflight_notify = true;

    idx = vq->inflight_region->last_batch_head;
    while (batch_size) {
        vq->inflight_region->desc[idx].inflight = 0;
        idx = vq->inflight_region->desc[idx].next;
        batch_size--;
    }
    vq->inflight_region->used_idx = vq->used->idx;
}

int virtio_virtq_attach(struct virtio_virtq* vq,
                        void* desc_addr,
                        void* avail_addr,
                        void* used_addr,
                        int qsz,
                        int avail_base,
                        void* inflight_addr)
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
    pthread_mutex_init(&vq->lock, NULL);

    /* Inflight initialization. */
    vq->inflight_region = inflight_addr;
    vq->inflight_notify = false;
    /* Make check on the first virtq dequeue. */
    vq->inflight_check = true;
    virtq_inflight_reconnect_update(vq);

    /* Notify fd is set separately */
    vq->notify_fd = -1;

    return 0;
}

void virtio_virtq_release(struct virtio_virtq* vq)
{
    if (vq) {
        pthread_mutex_destroy(&vq->lock);
        vhd_free(vq->buffers);
    }
}

struct inflight_resubmit {
    uint64_t counter;
    uint16_t head;
};

static int inflight_resubmit_compare(const void *first, const void *second)
{
    struct inflight_resubmit *left = (struct inflight_resubmit *)first;
    struct inflight_resubmit *right = (struct inflight_resubmit *)second;

    if (left->counter < right->counter) {
        return -1;
    }
    /* Can't return 0, since counter values are always different. */

    return 1;
}

/* Resubmit inflight requests on the virtqueue start. */
static int virtq_inflight_resubmit(struct virtio_virtq* vq,
                       struct virtio_mm_ctx* mm,
                       virtq_handle_buffers_cb handle_buffers_cb,
                       void* arg)
{
    uint16_t desc_num;
    uint16_t cnt;
    struct inflight_resubmit *resubmit_array;
    int i;
    int res;

    if (!vq->inflight_region) {
        return 0;
    }

    desc_num = vq->inflight_region->desc_num;
    cnt = 0;
    resubmit_array = alloca(sizeof(*resubmit_array) * desc_num);
    for (i = 0; i < desc_num; i++) {
        if (vq->inflight_region->desc[i].inflight) {
            resubmit_array[cnt].counter = vq->inflight_region->desc[i].counter;
            resubmit_array[cnt].head = i;
            cnt++;
        }
    }
    qsort(resubmit_array, cnt, sizeof(*resubmit_array),
            inflight_resubmit_compare);

    res = 0;
    VHD_LOG_DEBUG("cnt = %d inflight requests should be resubmitted", cnt);
    for (i = 0; i < cnt; i++) {
        res = virtq_dequeue_one(vq, mm, resubmit_array[i].head,
                handle_buffers_cb, arg);
        if (res) {
            break;
        }
    }

    return res;
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

static int walk_indirect_table(struct virtio_virtq* vq,
                               struct virtio_mm_ctx* mm,
                               const struct virtq_desc* table_desc)
{
    int res;
    struct virtq_desc desc;

    /* TODO: we need to validate that descriptor table memory, addressed by table_desc,
     * is a valid mapping for this device/guest. */

    if (table_desc->len == 0 || table_desc->len % sizeof(desc)) {
        VHD_LOG_ERROR("Bad indirect descriptor table length %d", table_desc->len);
        return -EINVAL;
    }

    void* mapped_table = virtio_map_guest_phys_range(mm, table_desc->addr, table_desc->len);
    if (!mapped_table) {
        VHD_LOG_ERROR("Bad guest address range on indirect descriptor table");
        return -EINVAL;
    }

    int max_indirect_descs = table_desc->len / sizeof(desc); 
    int chain_len = 0;

    struct virtq_desc* pdesc = (struct virtq_desc*) mapped_table;
    struct virtq_desc* pdesc_first = (struct virtq_desc*) mapped_table;
    struct virtq_desc* pdesc_last = (pdesc_first + max_indirect_descs - 1);

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
        res = map_buffer(vq, mm, desc.addr, desc.len, desc.flags & VIRTQ_DESC_F_WRITE);
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

int virtq_dequeue_many(struct virtio_virtq* vq,
                       struct virtio_mm_ctx* mm,
                       virtq_handle_buffers_cb handle_buffers_cb,
                       void* arg)
{
    int res;
    uint16_t head;
    uint16_t i;
    uint16_t num_avail;

    if (virtq_is_broken(vq)) {
        VHD_LOG_ERROR("virtqueue is broken, cannot process");
        return -ENODEV;
    }

    if (vq->inflight_check) {
        /* Check for the inflight requests once at the start. */
        VHD_LOG_DEBUG("resubmit inflight requests, if any");
        res = virtq_inflight_resubmit(vq, mm, handle_buffers_cb, arg);
        if (res) {
            goto queue_broken;
        }
        vq->inflight_check = false;
    }

    /* Limit this run to initial number of advertised descriptors.
     * TODO: limit it better in client */
    num_avail = vq->avail->idx - vq->last_avail;
    if (!num_avail) {
        return 0;
    }

    /* Make sure that further desc reads do not pass avail->idx read.
     * Not nessesary on x86_64, which is why rmb is really defined as a compiler barrier. */
    vhd_smp_rmb();

    /* TODO: disable extra notifies from this point */

    for (i = 0; i < num_avail; ++i) {
        /* Grab next descriptor head */
        head = vq->avail->ring[vq->last_avail % vq->qsz];
        res = virtq_dequeue_one(vq, mm, head, handle_buffers_cb, arg);
        if (res) {
            goto queue_broken;
        }

        virtq_inflight_avail_update(vq, head);
    }

    /* TODO: restore notifier mask here */
    return 0;

queue_broken:
    mark_broken(vq);
    return res;
}

static int virtq_dequeue_one(struct virtio_virtq* vq,
        struct virtio_mm_ctx* mm, uint16_t head,
        virtq_handle_buffers_cb handle_buffers_cb, void* arg)
{
    uint16_t descnum;
    uint16_t chain_len = 0;
    struct virtq_desc desc;
    int res;

    /* Reset stored vectors position */
    vq->next_buffer = 0;

    descnum = head;
    /* Walk descriptor chain */
    do {
        /* Check that descriptor is in-bounds */
        if (descnum >= vq->qsz) {
            VHD_LOG_ERROR("Descriptor num %d is out-of-bounds", descnum);
            return -EINVAL;
        }

        /* We explicitly make a local copy here to avoid any possible TOCTOU problems. */
        memcpy(&desc, vq->desc + descnum, sizeof(desc));
        VHD_LOG_DEBUG("head = %d: addr = 0x%llx, len = %d", head, (unsigned long long) desc.addr, desc.len);

        if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
            /* 2.4.5.3.1: A driver MUST NOT set both VIRTQ_DESC_F_INDIRECT and VIRTQ_DESC_F_NEXT in flags */
            if (desc.flags & VIRTQ_DESC_F_NEXT) {
                VHD_LOG_ERROR("Can't handle indirect descriptors and next flag");
                return -EINVAL;
            }

            res = walk_indirect_table(vq, mm, &desc);
            if (res != 0) {
                return res;
            }

            /* Descriptor chain should always terminate on indirect,
             * which means we should not see NEXT flag anymore, and we have checked exactly that above.
             * We document our assumption with an assert here. */
            VHD_ASSERT((desc.flags & VIRTQ_DESC_F_NEXT) == 0);

        } else {
            res = map_buffer(vq, mm, desc.addr, desc.len, desc.flags & VIRTQ_DESC_F_WRITE);
            if (res != 0) {
                /* We always reserve space beforehand, so this is a descriptor loop */
                VHD_LOG_ERROR("Descriptor loop found, vring is broken");
                return -EINVAL;
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
    handle_buffers_cb(arg, vq, &priv->iov);

    vq->last_avail++;

    return 0;
}

void virtq_commit_buffers(struct virtio_virtq* vq, struct virtio_iov* iov)
{
    VHD_VERIFY(vq);

    /* Put buffer head index and len into used ring */
    struct virtq_iov_private* priv = containerof(iov, struct virtq_iov_private, iov);
    pthread_mutex_lock(&vq->lock);
    struct virtq_used_elem* used = &vq->used->ring[vq->used->idx % vq->qsz];
    used->id = priv->used_head;
    used->len = priv->used_len;

    virtq_inflight_used_update(vq, used->id);

    vhd_smp_wmb();
    vq->used->idx++;

    virtq_inflight_used_commit(vq, used->id);
    pthread_mutex_unlock(&vq->lock);
    VHD_LOG_DEBUG("head = %d", priv->used_head);

    free_iov(priv);
}

void virtq_notify(struct virtio_virtq* vq)
{
    VHD_VERIFY(vq);

    /* TODO: check for notification mask! */
    if (vq->notify_fd != -1) {
        eventfd_write(vq->notify_fd, 1);
    }
}

void virtq_set_notify_fd(struct virtio_virtq* vq, int fd)
{
    VHD_VERIFY(vq);

    if (vq->notify_fd != -1 && vq->notify_fd != fd) {
        close(vq->notify_fd);
    }

    vq->notify_fd = fd;

    /* TODO: We should send a notify here, because the previous disconnect
     * happened before the notify event.
     * Maybe we shouldn't handle it, but it looks like a correct way to handle.
     */
    if (vq->inflight_notify) {
        virtq_notify(vq);
    }
    vq->inflight_notify = false;
}
