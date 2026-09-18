#pragma once

#include <stdint.h>
#include <vector>
#include <functional>

#include "virtio/virt_queue.h"

namespace virtio_test {

constexpr uint16_t default_queue_size = 1024;

/* Buffer io direction from "device" point of view */
enum iodir {
    device_read,    /* Device will read from buffer */
    device_write,   /* Device will write to buffer */

    /* Driver point of view for convinience */
    req_read = device_write,
    req_write = device_read,
};

struct q_iovec {
    void *addr;
    size_t len;
    int dir; /* iodir */

    q_iovec(void *_addr, size_t _len, iodir _dir = iodir::device_read)
        : addr(_addr), len(_len), dir(_dir)
    {}

    q_iovec(uintptr_t _addr, size_t _len, iodir _dir = iodir::device_read)
        : q_iovec((void *)_addr, _len, _dir)
    {}
};

struct queue_data {
    uint16_t qsz;
    std::vector<struct virtq_desc> descriptors;
    std::vector<uint8_t> avail;
    std::vector<uint8_t> used;

    virtq_desc *desc_table = nullptr;
    virtq_avail *avail_ring = nullptr;
    virtq_used *used_ring = nullptr;
    struct inflight_split_region *inflight_region = nullptr;

    uint16_t next_free_desc = 0;
    uint16_t last_used_idx = 0;

    explicit queue_data(uint16_t num_desc = default_queue_size) :
        qsz(num_desc),
        descriptors(qsz),
        avail(sizeof(virtq_avail) + sizeof(uint16_t) * qsz
              + sizeof(uint16_t)),
        used(sizeof(virtq_used) + sizeof(virtq_used_elem) * qsz
             + sizeof(uint16_t))
    {
        desc_table = (virtq_desc *) descriptors.data();
        for (virtq_desc &d : descriptors) {
            memset(&d, 0, sizeof(d));
        }

        avail_ring = (virtq_avail *) avail.data();
        avail_ring->flags = 0;
        avail_ring->idx = 0;

        used_ring = (virtq_used *) used.data();
        used_ring->flags = 0;
        used_ring->idx = 0;

        size_t inflight_size = sizeof(struct inflight_split_region) +
            sizeof(struct inflight_split_desc) * qsz;
        inflight_region =
            (struct inflight_split_region *) ::operator new(inflight_size);
        memset(inflight_region, 0, inflight_size);
        inflight_region->version = 0x1;
        inflight_region->desc_num = num_desc;
    }

    ~queue_data()
    {
        ::operator delete(inflight_region);
    }

    queue_data(const queue_data &) = delete;
    queue_data &operator= (const queue_data &) = delete;

    uint16_t next_free_desc_num()
    {
        uint16_t num = next_free_desc++;
        return num % qsz;
    }

    virtq_desc *get_desc(uint16_t idx)
    {
        return desc_table + idx;
    }

    struct inflight_split_region *get_inflight_region(void)
    {
        return inflight_region;
    }

    struct inflight_split_desc *get_inflight_desc(uint16_t idx)
    {
        return &inflight_region->desc[idx];
    }

    void attach_virtq(virtio_virtq *vq)
    {
        *vq = (struct virtio_virtq) {
            .log_tag = "test_vq",
            .desc = desc_table,
            .avail = avail_ring,
            .used = used_ring,
            .used_gpa_base = 0x1, /* to pass virtio_virtq_init check */
            .qsz = qsz,
            .last_avail = used_ring->idx,
            .inflight_region = inflight_region,
        };

        virtio_virtq_init(vq);
    }

    uint16_t build_descriptor_chain(const std::vector<q_iovec> &chain)
    {
        uint16_t head = next_free_desc;
        virtq_desc *prev = nullptr;

        for (const auto &vec : chain) {
            uint16_t num = next_free_desc_num();
            virtq_desc *pdesc = desc_table + num;

            pdesc->addr = (uintptr_t)vec.addr;
            pdesc->len = vec.len;
            pdesc->flags =
                (vec.dir == iodir::device_write ? VIRTQ_DESC_F_WRITE : 0);
            if (prev) {
                prev->flags |= VIRTQ_DESC_F_NEXT;
                prev->next = num;
            }

            prev = pdesc;
        }

        return head;
    }

    uint16_t build_indirect_descriptor_chain(const std::vector<q_iovec> &chain,
                                             std::vector<virtq_desc> &out_table)
    {
        /* Create and fill table buffer */
        out_table.resize(chain.size());
        for (size_t i = 0; i < chain.size(); ++i) {
            virtq_desc &desc = out_table[i];
            desc.addr = (uintptr_t)chain[i].addr;
            desc.len = chain[i].len;
            desc.flags =
                (chain[i].dir == iodir::device_write ? VIRTQ_DESC_F_WRITE : 0);
            if (i != 0) {
                out_table[i - 1].flags |= VIRTQ_DESC_F_NEXT;
                out_table[i - 1].next = i;
            }
        }

        /* Allocate descriptor to hold indirect table ref */
        uint16_t head = next_free_desc_num();
        virtq_desc *pdesc = desc_table + head;
        pdesc->addr = (uintptr_t)out_table.data();
        pdesc->len = out_table.size() * sizeof(virtq_desc);
        pdesc->flags = VIRTQ_DESC_F_INDIRECT;

        return head;
    }

    uint16_t connect_chains(uint16_t dir_head, uint16_t indir_head)
    {
        virtq_desc *ptail = desc_table + dir_head;
        while (ptail->flags & VIRTQ_DESC_F_NEXT) {
            ptail = desc_table + ptail->next;
        }

        ptail->flags |= VIRTQ_DESC_F_NEXT;
        ptail->next = indir_head;
        return dir_head;
    }

    typedef std::function<void(virtio_iov *)> buffers_handler_func;

    static void buffers_handler_cb(void *arg, virtio_virtq *vq, virtio_iov *iov)
    {
        buffers_handler_func *fptr = (buffers_handler_func *) arg;
        (*fptr)(iov);
    }

    void publish_avail(uint16_t head)
    {
        /* TODO: release semantics on idx */
        avail_ring->ring[avail_ring->idx] = head;
        avail_ring->idx++;
    }

    int kick_virtq(virtio_virtq *vq, buffers_handler_func func)
    {
        return virtq_dequeue_many(vq, buffers_handler_cb, &func);
    }

    void commit_buffers(virtio_virtq *vq, virtio_iov *iov, uint32_t len)
    {
        /* TODO: free list tracking? */
        virtq_push(vq, iov, len);
        virtio_free_iov(iov);
    }

    std::vector<virtq_used_elem> collect_used()
    {
        std::vector<virtq_used_elem> used_heads;
        while (last_used_idx < used_ring->idx) {
            used_heads.push_back(used_ring->ring[last_used_idx % qsz]);
            last_used_idx++;
        }

        return used_heads;
    }
};

struct desc_chain {
    bool is_indirect;
    std::vector<q_iovec> buffers;

    /* In case of indirect chain we can use this to store descriptor table */
    mutable std::vector<virtq_desc> indir_table;

    desc_chain()
    {}

    desc_chain(bool _is_indirect,
               const std::vector<virtio_test::q_iovec> &_buffers) :
        is_indirect(_is_indirect), buffers(_buffers)\
    {}

    static desc_chain with_buffers(
        const std::vector<virtio_test::q_iovec> &buffers)
    {
        return desc_chain(false, buffers);
    }

    static desc_chain indirect_with_buffers(
        const std::vector<virtio_test::q_iovec> &buffers)
    {
        return desc_chain(true, buffers);
    }
};

} /* namespace virtio_test */
