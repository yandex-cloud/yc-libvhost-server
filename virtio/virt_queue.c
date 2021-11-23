#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/eventfd.h>
#include <time.h>

#include "catomic.h"
#include "virt_queue.h"
#include "logging.h"
#include "memmap.h"
#include "memlog.h"

/**
 * Holds private virtq data together with iovs we show users
 */
struct virtq_iov_private {
    /* Private virtq fields */
    uint16_t used_head;
    uint16_t used_len;
    struct vhd_memory_map *mm;

    /* Iov we show to caller */
    struct virtio_iov iov;
};

static inline uint16_t virtq_get_used_event(struct virtio_virtq *vq)
{
    return vq->avail->ring[vq->qsz];
}

static inline void virtq_set_avail_event(struct virtio_virtq *vq,
                                         uint16_t avail_idx)
{
    *(le16 *)&vq->used->ring[vq->qsz] = avail_idx;
}

static int virtq_dequeue_one(struct virtio_virtq *vq, uint16_t head,
                             virtq_handle_buffers_cb handle_buffers_cb,
                             void *arg, bool resubmit);

static struct virtq_iov_private *alloc_iov(uint16_t nvecs)
{
    size_t size = sizeof(struct virtq_iov_private)
                + sizeof(struct vhd_buffer) * nvecs;

    struct virtq_iov_private *priv = vhd_alloc(size);
    priv->iov.nvecs = nvecs;
    return priv;
}

void virtio_free_iov(struct virtio_iov *iov)
{
    struct virtq_iov_private *priv =
        containerof(iov, struct virtq_iov_private, iov);
    vhd_free(priv);
}

uint16_t virtio_iov_get_head(struct virtio_iov *iov)
{
    struct virtq_iov_private *priv =
        containerof(iov, struct virtq_iov_private, iov);
    return priv->used_head;
}

static int add_buffer(struct virtio_virtq *vq, void *addr, size_t len,
                      bool write_only)
{
    if (vq->next_buffer == vq->qsz) {
        /*
         * We always reserve space beforehand, so this is a descriptor
         * loop
         */
        VHD_OBJ_ERROR(vq, "Descriptor loop found, vring is broken");
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

static int map_buffer(struct virtio_virtq *vq, uint64_t gpa, size_t len,
                      bool write_only)
{
    void *addr = gpa_range_to_ptr(vq->mm, gpa, len);
    if (!addr) {
        VHD_OBJ_ERROR(vq, "Failed to map GPA 0x%lx, vring is broken", gpa);
        return -EINVAL;
    }

    return add_buffer(vq, addr, len, write_only);
}

/* Modify inflight descriptor after dequeue request from the available ring. */
static void virtq_inflight_avail_update(struct virtio_virtq *vq, uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    if (vq->inflight_region->desc[head].inflight) {
        VHD_OBJ_WARN(vq, "iflight[%u]=%u (expected 0)", head,
                     vq->inflight_region->desc[head].inflight);
    }

    vq->inflight_region->desc[head].counter = vq->req_cnt;
    vq->req_cnt++;
    vq->inflight_region->desc[head].inflight = 1;
}

/* Prepare the inflight descriptor for commit. */
static void virtq_inflight_used_update(struct virtio_virtq *vq, uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    vq->inflight_region->desc[head].next = vq->inflight_region->last_batch_head;
    vq->inflight_region->last_batch_head = head;
}

/* Post commit inflight descriptor handling. */
static void virtq_inflight_used_commit(struct virtio_virtq *vq, uint16_t head)
{
    if (!vq->inflight_region) {
        return;
    }

    if (vq->inflight_region->desc[head].inflight != 1) {
        VHD_OBJ_WARN(vq, "iflight[%u]=%u (expected 1)", head,
                     vq->inflight_region->desc[head].inflight);
    }

    vq->inflight_region->desc[head].inflight = 0;
    /*
     * Make sure used_idx is stored after the desc content, so that the next
     * incarnation of the vhost backend sees consistent values regardless of
     * where the current one dies.  There's no concurrent access to the
     * inflight region so only a compiler barrier is necessary.
     */
    barrier();
    vq->inflight_region->used_idx = vq->used->idx;
}

/*
 * If the value of ``used_idx`` does not match the ``idx`` value of
 * used ring (means the inflight field of ``inflight_split_desc``
 * entries in last batch may be incorrect).
 */
static void virtq_inflight_reconnect_update(struct virtio_virtq *vq)
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

    idx = vq->inflight_region->last_batch_head;
    while (batch_size) {
        vq->inflight_region->desc[idx].inflight = 0;
        idx = vq->inflight_region->desc[idx].next;
        batch_size--;
    }
    vq->inflight_region->used_idx = vq->used->idx;
}

static void virtio_virtq_reset_stat(struct virtio_virtq *vq)
{
    memset(&vq->stat, 0, sizeof(vq->stat));
}

void virtio_virtq_init(struct virtio_virtq *vq)
{
    VHD_ASSERT(!vq->buffers);
    vq->buffers = vhd_calloc(vq->qsz, sizeof(vq->buffers[0]));

    /* Make check on the first virtq dequeue. */
    vq->inflight_check = true;
    virtq_inflight_reconnect_update(vq);

    virtio_virtq_reset_stat(vq);
}

void virtio_virtq_release(struct virtio_virtq *vq)
{
    VHD_ASSERT(vq->buffers);
    vhd_free(vq->buffers);
    *vq = (struct virtio_virtq) {};
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
static int virtq_inflight_resubmit(struct virtio_virtq *vq,
                                   virtq_handle_buffers_cb handle_buffers_cb,
                                   void *arg)
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
    VHD_OBJ_DEBUG(vq, "cnt = %d inflight requests should be resubmitted", cnt);
    for (i = 0; i < cnt; i++) {
        res = virtq_dequeue_one(vq, resubmit_array[i].head,
                                handle_buffers_cb, arg, true);
        if (res) {
            break;
        }
    }

    return res;
}

bool virtq_is_broken(struct virtio_virtq *vq)
{
    return vq->broken;
}

static void mark_broken(struct virtio_virtq *vq)
{
    vq->broken = true;
}

static int walk_indirect_table(struct virtio_virtq *vq,
                               const struct virtq_desc *table_desc)
{
    int res;
    struct virtq_desc desc;

    if (table_desc->len == 0 || table_desc->len % sizeof(desc)) {
        VHD_OBJ_ERROR(vq, "Bad indirect descriptor table length %d",
                      table_desc->len);
        return -EINVAL;
    }

    void *mapped_table = gpa_range_to_ptr(vq->mm, table_desc->addr,
                                          table_desc->len);
    if (!mapped_table) {
        VHD_OBJ_ERROR(vq,
                      "Bad guest address range on indirect descriptor table");
        return -EINVAL;
    }

    int max_indirect_descs = table_desc->len / sizeof(desc);
    int chain_len = 0;

    struct virtq_desc *pdesc = (struct virtq_desc *) mapped_table;
    struct virtq_desc *pdesc_first = (struct virtq_desc *) mapped_table;
    struct virtq_desc *pdesc_last = (pdesc_first + max_indirect_descs - 1);

    do {
        /* Descriptor should point inside indirect table */
        if (pdesc < pdesc_first || pdesc > pdesc_last) {
            VHD_OBJ_ERROR(vq, "Indirect descriptor %p is out of table bounds",
                          pdesc);
            return -EINVAL;
        }

        memcpy(&desc, pdesc, sizeof(desc));

        /*
         * 2.4.5.3.1: "The driver MUST NOT set the VIRTQ_DESC_F_INDIRECT flag
         * within an indirect descriptor"
         */
        if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
            return -EINVAL;
        }

        /*
         * 2.4.5.3.1: "A driver MUST NOT create a descriptor chain longer than
         * the Queue Size of the device"
         * Indirect descriptors are part of the chain and should abide by this
         * requirement
         */
        res = map_buffer(vq, desc.addr, desc.len,
                         desc.flags & VIRTQ_DESC_F_WRITE);
        if (res != 0) {
            VHD_OBJ_ERROR(vq, "Descriptor loop found, vring is broken");
            return -EINVAL;
        }

        /* Indirect descriptors are still chained by next pointer */
        pdesc = pdesc_first + pdesc->next;
        ++chain_len;

    } while (desc.flags & VIRTQ_DESC_F_NEXT);

    /*
     * Looks like it is valid when chain len is not equal to table size, but it
     * looks iffy.
     */
    if (chain_len != max_indirect_descs) {
        VHD_OBJ_INFO(vq, "Indirect chain length %d is not equal to table size "
                     "%d, which looks strange", chain_len, max_indirect_descs);
    }

    return 0;
}

int virtq_dequeue_many(struct virtio_virtq *vq,
                       virtq_handle_buffers_cb handle_buffers_cb,
                       void *arg)
{
    int res;
    uint16_t head;
    uint16_t i;
    uint16_t num_avail;
    uint16_t avail, avail2;
    time_t now;

    if (virtq_is_broken(vq)) {
        VHD_OBJ_ERROR(vq, "virtqueue is broken, cannot process");
        return -ENODEV;
    }

    if (vq->inflight_check) {
        /* Check for the inflight requests once at the start. */
        VHD_OBJ_DEBUG(vq, "resubmit inflight requests, if any");
        res = virtq_inflight_resubmit(vq, handle_buffers_cb, arg);
        if (res) {
            goto queue_broken;
        }
        vq->inflight_check = false;
    }

    now = time(NULL);

    if (now - vq->stat.period_start_ts > 60) {
        vq->stat.period_start_ts = now;
        vq->stat.metrics.queue_len_max_60s = 0;
    }

    vq->stat.metrics.dispatch_total++;

    /*
     * Limit this run to initial number of advertised descriptors.
     * TODO: limit it better in client
     */
    avail = vq->avail->idx;
    smp_mb(); /* avail->idx read followed by avail_event write */
    if (vq->has_event_idx) {
        while (true) {
            virtq_set_avail_event(vq, avail);
            smp_mb(); /* avail_event write followed by avail->idx read */
            avail2 = vq->avail->idx;
            if (avail2 == avail) {
                break;
            }
            smp_mb(); /* avail->idx read followed by avail_event write */
            avail = avail2;
        }
    }

    num_avail = avail - vq->last_avail;

    if (!num_avail) {
        vq->stat.metrics.dispatch_empty++;
        return 0;
    }

    vq->stat.metrics.queue_len_last = num_avail;
    if (vq->stat.metrics.queue_len_last > vq->stat.metrics.queue_len_max_60s) {
        vq->stat.metrics.queue_len_max_60s = vq->stat.metrics.queue_len_last;
    }

    /* Make sure that further desc reads do not pass avail->idx read. */
    smp_rmb();                  /* barrier pair [A] */

    /* TODO: disable extra notifies from this point */

    for (i = 0; i < num_avail; ++i) {
        /* Grab next descriptor head */
        head = vq->avail->ring[vq->last_avail % vq->qsz];
        res = virtq_dequeue_one(vq, head, handle_buffers_cb, arg, false);
        if (res) {
            goto queue_broken;
        }

        vq->stat.metrics.request_total++;
    }

    /* TODO: restore notifier mask here */
    return 0;

queue_broken:
    mark_broken(vq);
    return res;
}

static int virtq_dequeue_one(struct virtio_virtq *vq, uint16_t head,
                             virtq_handle_buffers_cb handle_buffers_cb,
                             void *arg, bool resubmit)
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
            VHD_OBJ_ERROR(vq, "Descriptor num %d is out-of-bounds", descnum);
            return -EINVAL;
        }

        /*
         * We explicitly make a local copy here to avoid any possible TOCTOU
         * problems.
         */
        memcpy(&desc, vq->desc + descnum, sizeof(desc));
        VHD_OBJ_DEBUG(vq, "head = %d: addr = 0x%llx, len = %d", head,
                      (unsigned long long) desc.addr, desc.len);

        if (desc.flags & VIRTQ_DESC_F_INDIRECT) {
            /*
             * 2.4.5.3.1: A driver MUST NOT set both VIRTQ_DESC_F_INDIRECT and
             * VIRTQ_DESC_F_NEXT in flags
             */
            if (desc.flags & VIRTQ_DESC_F_NEXT) {
                VHD_OBJ_ERROR(vq, "Can't handle indirect descriptors "
                              "and next flag");
                return -EINVAL;
            }

            res = walk_indirect_table(vq, &desc);
            if (res != 0) {
                return res;
            }
        } else {
            res = map_buffer(vq, desc.addr, desc.len,
                             desc.flags & VIRTQ_DESC_F_WRITE);
            if (res != 0) {
                return res;
            }
        }

        /* next desc is not touched if loop terminated */
        descnum = desc.next;
        chain_len++;
    } while (desc.flags & VIRTQ_DESC_F_NEXT);

    /* Create iov copy from stored buffer for client handling */
    struct virtq_iov_private *priv = alloc_iov(vq->next_buffer);
    memcpy(priv->iov.buffers, vq->buffers,
           priv->iov.nvecs * sizeof(vq->buffers[0]));
    priv->used_head = head;
    priv->used_len = chain_len;
    priv->mm = vq->mm;
    /* matched with unref in virtq_commit_buffers */
    vhd_memmap_ref(priv->mm);

    if (!resubmit) {
        virtq_inflight_avail_update(vq, head);
    }

    /* Send this over to handler */
    handle_buffers_cb(arg, vq, &priv->iov);

    vq->last_avail++;

    return 0;
}

static void vhd_log_buffers(struct vhd_memory_log *log,
                            struct vhd_memory_map *mm,
                            struct virtio_iov *iov)
{
    int nvecs = iov->nvecs;
    int i;
    for (i = 0; i < nvecs; ++i) {
        if (iov->buffers[i].write_only) {
            vhd_mark_range_dirty(log, mm, iov->buffers[i].base,
                                 iov->buffers[i].len);
        }
    }
}

/*
 * NOTE: this @mm is the one the request was started with, not the current one
 * on @vq
 */
static void vhd_log_modified(struct virtio_virtq *vq,
                             struct vhd_memory_map *mm,
                             struct virtio_iov *iov,
                             uint16_t used_idx)
{
    /* log modifications of buffers in descr */
    vhd_log_buffers(vq->log, mm, iov);
    if (vq->flags & VHOST_VRING_F_LOG) {
        /* log modification of used->idx */
        vhd_mark_gpa_range_dirty(vq->log,
                                 vq->used_gpa_base +
                                 offsetof(struct virtq_used, idx),
                                 sizeof(vq->used->idx));
        /* log modification of used->ring[idx] */
        vhd_mark_gpa_range_dirty(vq->log,
                                 vq->used_gpa_base +
                                 offsetof(struct virtq_used, ring[used_idx]),
                                 sizeof(vq->used->ring[0]));
    }
}

static void virtq_do_notify(struct virtio_virtq *vq)
{
    if (vq->notify_fd != -1) {
        eventfd_write(vq->notify_fd, 1);
    }
}

void virtq_notify(struct virtio_virtq *vq)
{
    if (!vq->has_event_idx) {
        /*
         * Virtio specification v1.0, 5.1.6.2.3:
         * Often a driver will suppress transmission interrupts using the
         * VIRTQ_AVAIL_F_NO_INTERRUPT flag (see 3.2.2 Receiving Used Buffers
         * From The Device) and check for used packets in the transmit path
         * of following packets.
         */
        if (!(vq->avail->flags & VIRTQ_AVAIL_F_NO_INTERRUPT)) {
            virtq_do_notify(vq);
        }

        return;
    }

    smp_mb(); /* used->idx write followed by used_event read */

    /*
     * Virtio specification v1.0, 2.4.7.2:
     * if the VIRTIO_F_EVENT_IDX feature bit is negotiated:
     * The device MUST ignore the lower bit of flags.
     * If the idx field in the used ring was
     * equal to used_event, the device MUST send an interrupt.
     * --------------------------------------------------------
     * Note: code below assumes that virtq_notify is always called
     * per one completion, and never per batch.
     */
    if (virtq_get_used_event(vq) == (uint16_t)(vq->used->idx - 1)) {
        virtq_do_notify(vq);
    }
}

void virtq_commit_buffers(struct virtio_virtq *vq, struct virtio_iov *iov)
{
    /* Put buffer head index and len into used ring */
    struct virtq_iov_private *priv = containerof(iov, struct virtq_iov_private,
                                                 iov);
    uint16_t used_idx = vq->used->idx % vq->qsz;
    struct virtq_used_elem *used = &vq->used->ring[used_idx];
    used->id = priv->used_head;
    used->len = priv->used_len;

    virtq_inflight_used_update(vq, used->id);

    smp_wmb();                  /* barrier pair [A] */
    vq->used->idx++;

    virtq_inflight_used_commit(vq, used->id);
    VHD_OBJ_DEBUG(vq, "head = %d", priv->used_head);

    /* use memmap the request was started with rather than the current one */
    if (vq->log) {
        vhd_log_modified(vq, priv->mm, &priv->iov, used_idx);
    }

    /* matched with ref in virtq_dequeue_one */
    vhd_memmap_unref(priv->mm);
    vhd_free(priv);

    virtq_notify(vq);
}

void virtq_set_notify_fd(struct virtio_virtq *vq, int fd)
{
    vq->notify_fd = fd;

    /*
     * Always notify new fd because on initial setup QEMU sets up kick_fd
     * before call_fd, so before call_fd becomes configured there can be
     * already processed descriptors that guest wasn't notified about.
     * And on reconnect connection may have been lost before the server has
     * had a chance to signal guest.
     */
    virtq_do_notify(vq);
}

void virtio_virtq_get_stat(struct virtio_virtq *vq,
                           struct vhd_vq_metrics *metrics)
{
    metrics->request_total = vq->stat.metrics.request_total;
    metrics->dispatch_total = vq->stat.metrics.dispatch_total;
    metrics->dispatch_empty = vq->stat.metrics.dispatch_empty;
    metrics->queue_len_last = vq->stat.metrics.queue_len_last;
    metrics->queue_len_max_60s = vq->stat.metrics.queue_len_max_60s;
}
