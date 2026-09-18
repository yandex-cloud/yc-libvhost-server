#include <stdlib.h>
#include <stdio.h>

#include <vector>
#include <deque>
#include <memory>
#include <algorithm>

#include <CUnit/Basic.h>

#include "virtio/virt_queue.h"

#include "qdata.h"

#include "memmap.h"
#include "logging.h"
#include "../test_utils.h"

using namespace virtio_test;

// virtio memory mapper mock
extern "C" {
void *gpa_range_to_ptr(struct vhd_memory_map *mm, uint64_t gpa, size_t len)
{
    return (void *)gpa;
}

void vhd_memmap_ref(struct vhd_memory_map *mm)
{
}

void vhd_memmap_unref(struct vhd_memory_map *mm)
{
}
}

static void validate_buffers(const std::vector<q_iovec> &buffers,
                             const virtio_iov *iov)
{
    size_t total_bytes = 0;
    size_t niov = iov->niov_in + iov->niov_out;
    std::for_each(buffers.begin(), buffers.end(),
                  [&](const q_iovec& vec) { total_bytes += vec.len; });

    CU_ASSERT(niov == buffers.size());

    for (size_t i = 0; i < niov; ++i) {
        CU_ASSERT(iov->buffers[i].base == (void *)buffers[i].addr);
        CU_ASSERT(iov->buffers[i].len == buffers[i].len);
    }
}

/* Check the state of the inflight region. Check the number of
 * committed requests.
 */
static void validate_inflight_region(queue_data &qd,
        int expected_num)
{
    struct inflight_split_region *ireg = qd.get_inflight_region();

    CU_ASSERT(ireg->used_idx == expected_num);
}

/* Check the state of the inflight descriptors. Check the following:
 * 1. All the head descriptors should be in the expected_state inflight state.
 * 2. Number of descriptors to check should be expected_size.
 */
static void validate_inflight_buffers(queue_data &qd,
        const std::deque<uint16_t> heads,
        size_t expected_size, bool expected_state)
{
    CU_ASSERT(heads.size() == expected_size);
    for (const auto &head : heads) {
        struct inflight_split_desc *idesc = qd.get_inflight_desc(head);
        CU_ASSERT(idesc->inflight == expected_state);
        // It is assumed that buffers are committed sequentially.
        // If not, then this counter check should be skipped.
        CU_ASSERT(idesc->counter == head + 1u);
    }
}

static void validate_chain(queue_data &qdata,
                           virtio_virtq &vq,
                           const desc_chain &chain)
{
    int res = 0;
    static const uint32_t len = 42;

    uint16_t head = (chain.is_indirect ?
            qdata.build_indirect_descriptor_chain(chain.buffers,
                                                  chain.indir_table) :
            qdata.build_descriptor_chain(chain.buffers));

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            validate_buffers(chain.buffers, iov);
            qdata.commit_buffers(&vq, iov, len);
        }
    );

    CU_ASSERT(res == 0);

    std::vector<virtq_used_elem> used_heads = qdata.collect_used();

    // 1 chain - 1 used head
    CU_ASSERT_FATAL(used_heads.size() == 1);
    CU_ASSERT(used_heads[0].id == head);
    CU_ASSERT(used_heads[0].len == len);
}

static void validate_chains(queue_data &qdata,
                           virtio_virtq &vq,
                           const std::vector<desc_chain> &chains)
{
    int res = 0;

    std::vector<uint16_t> heads;
    for (auto &chain : chains) {
        uint16_t head = (chain.is_indirect ?
            qdata.build_indirect_descriptor_chain(chain.buffers,
                                                  chain.indir_table) :
            qdata.build_descriptor_chain(chain.buffers));
        qdata.publish_avail(head);
        heads.push_back(head);
    }

    // All chains are advertised at once, buffers handler is called once per chain, in order
    int chain_num = 0;
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            const auto &chain = chains[chain_num];
            validate_buffers(chain.buffers, iov);
            qdata.commit_buffers(&vq, iov, chain_num);
            ++chain_num;
        }
    );

    CU_ASSERT(res == 0);

    std::vector<virtq_used_elem> used_heads = qdata.collect_used();

    CU_ASSERT_FATAL(used_heads.size() == heads.size());
    for (size_t i = 0; i < heads.size(); ++i) {
        CU_ASSERT(used_heads[i].id == heads[i]);
        CU_ASSERT(used_heads[i].len == i);
    }
}

static void direct_descriptors_test(void)
{
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain chain_single = desc_chain::with_buffers({
        {0xdeadf00d, 0x1000},
    });

    validate_chain(qdata, vq, chain_single);

    desc_chain chain_many = desc_chain::with_buffers({
        {0x00001000, 0x1000},
        {0x00002000, 0x2000},
        {0x00008000, 0x4000},
        {0x0000F000, 0x1000},
    });

    validate_chain(qdata, vq, chain_many);

    validate_chains(qdata, vq, {chain_many, chain_single, chain_many});

    virtio_virtq_release(&vq);
}

static void indirect_descriptors_test(void)
{
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain chain_single = desc_chain::indirect_with_buffers({
        {0xdeadf00d, 0x1000},
    });

    validate_chain(qdata, vq, chain_single);

    desc_chain chain_many = desc_chain::indirect_with_buffers({
        {0x00001000, 0x1000},
        {0x00002000, 0x2000},
        {0x00008000, 0x4000},
        {0x0000F000, 0x1000},
    });

    validate_chain(qdata, vq, chain_many);

    validate_chains(qdata, vq, {chain_many, chain_single, chain_many});

    virtio_virtq_release(&vq);
}

static void mixed_descriptors_test(void)
{
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain indir_chain = desc_chain::indirect_with_buffers({
        {0x00001000, 0x1000},
        {0x00002000, 0x2000},
        {0x00008000, 0x4000},
        {0x0000F000, 0x1000},
    });

    desc_chain dir_chain = desc_chain::with_buffers({
        {0xA0001000, 0x1000},
        {0xA0002000, 0x2000},
        {0xA0008000, 0x4000},
        {0xA000F000, 0x1000},
    });

    validate_chains(qdata, vq, {dir_chain, indir_chain, dir_chain});

    virtio_virtq_release(&vq);
}

static void combined_descriptor_chain_test(void)
{
    /* According to virtio spec, 2.4.5.3:
     *
     * "The device MUST handle the case of zero or more normal chained descriptors
     * followed by a single descriptor with flags&VIRTQ_DESC_F_INDIRECT.
     * Note: While unusual (most implementations either create a chain solely using non-indirect descriptors,
     * or use a single indirect element), such a layout is valid."
     *
     * We reproduce aformentioned unusual layout in this test
     */

    int res;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain indir_chain = desc_chain::indirect_with_buffers({
        {0x00001000, 0x1000},
        {0x00002000, 0x2000},
        {0x00008000, 0x4000},
        {0x0000F000, 0x1000},
    });

    uint16_t indir_head = qdata.build_indirect_descriptor_chain(
        indir_chain.buffers, indir_chain.indir_table);

    desc_chain dir_chain = desc_chain::with_buffers({
        {0xA0001000, 0x1000},
        {0xA0002000, 0x2000},
        {0xA0008000, 0x4000},
        {0xA000F000, 0x1000},
    });

    uint16_t head = qdata.build_descriptor_chain(dir_chain.buffers);
    head = qdata.connect_chains(head, indir_head);

    /* These are the buffers we should see in iov */
    std::vector<q_iovec> buffers;
    buffers.insert(buffers.end(), dir_chain.buffers.begin(),
                   dir_chain.buffers.end());
    buffers.insert(buffers.end(), indir_chain.buffers.begin(),
                   indir_chain.buffers.end());

    CU_ASSERT(buffers.size() ==
        (indir_chain.buffers.size() + dir_chain.buffers.size()));

    /* Publish only direct chain head */
    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            validate_buffers(buffers, iov);
            qdata.commit_buffers(&vq, iov, 0);
        }
    );

    CU_ASSERT(res == 0);

    virtio_virtq_release(&vq);
}

static void oob_descriptor_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    // Craft direct descriptor that has an OOB next field
    uint16_t head = qdata.next_free_desc_num();
    virtq_desc *pdesc = qdata.get_desc(head);
    pdesc->flags = VIRTQ_DESC_F_NEXT;
    pdesc->next = qdata.qsz;
    pdesc->addr = 0x1000;
    pdesc->len = 0x1000;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void indirect_oob_descriptor_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    // Craft indirect OOB descriptor
    desc_chain chain = desc_chain::indirect_with_buffers({
        {0x1000, 0x1000},
        {0x2000, 0x1000},
    });

    uint16_t head = qdata.build_indirect_descriptor_chain(chain.buffers,
                                                          chain.indir_table);
    virtq_desc *pdesc = &chain.indir_table.front();
    pdesc->next = chain.indir_table.size();

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void descriptor_loop_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    /* Build a valid descriptor chain */
    desc_chain chain_many = desc_chain::with_buffers({
        {0x00001000, 0x1000},
        {0x00002000, 0x2000},
        {0x00008000, 0x4000},
    });

    uint16_t head = qdata.build_descriptor_chain(chain_many.buffers);

    /*
     * And then corrupt it with cycle
     * [0]->[1]->[2]
     *       ^----'
     */
    virtq_desc *desc = qdata.get_desc(2);
    desc->next = 1;
    desc->flags = VIRTQ_DESC_F_NEXT;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void indirect_descriptor_loop_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    // Craft indirect descriptor loop
    desc_chain chain = desc_chain::indirect_with_buffers({
        {0x1000, 0x1000},
        {0x2000, 0x1000},
        {0x3000, 0x1000},
    });

    uint16_t head = qdata.build_indirect_descriptor_chain(chain.buffers,
                                                          chain.indir_table);

    chain.indir_table[2].flags = VIRTQ_DESC_F_NEXT;
    chain.indir_table[2].next = 1;
    chain.indir_table[1].next = 2;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov* iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void bad_indirect_descriptor_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain chain = desc_chain::with_buffers({
        {0x1000, 0x1000},
        {0x2000, 0x1000},
        {0x3000, 0x1000},
    });

    /* Descriptor cannot be both F_NEXT and F_INDIRECT */
    uint16_t head = qdata.build_descriptor_chain(chain.buffers);
    virtq_desc *pdesc = qdata.get_desc(head);
    pdesc->flags |= VIRTQ_DESC_F_INDIRECT;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void bad_indirect_descriptor_table_size_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    desc_chain chain = desc_chain::with_buffers({
        {0x1000, 0x1000},
        {0x2000, 0x1000},
        {0x3000, 0x1000},
    });

    /* Indirect descriptor table len should be aligned to descriptor size */
    uint16_t head = qdata.build_indirect_descriptor_chain(
        chain.buffers, chain.indir_table);
    virtq_desc *pdesc = qdata.get_desc(head);
    pdesc->len += 1;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

static void broken_queue_test(void)
{
    int res = 0;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);

    // Break virtq by sending an OOB descriptor
    uint16_t head = qdata.next_free_desc_num();
    virtq_desc *pdesc = qdata.get_desc(head);
    pdesc->flags = VIRTQ_DESC_F_NEXT;
    pdesc->next = qdata.qsz;
    pdesc->addr = 0x1000;
    pdesc->len = 0x1000;

    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);
    CU_ASSERT(virtq_is_broken(&vq));

    // Any further attempts to access queue should fail
    desc_chain dir_chain = desc_chain::with_buffers({
        {0xA0001000, 0x1000},
    });

    head = qdata.build_descriptor_chain(dir_chain.buffers);
    qdata.publish_avail(head);
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            CU_ASSERT(0 && "should never be called");
        }
    );
    CU_ASSERT(res != 0);

    // Still broken
    CU_ASSERT(virtq_is_broken(&vq));

    virtio_virtq_release(&vq);
}

/* This is the main test for the inflight/reconnect functionality.
 * The general steps are as follows:
 *   - Submit 10 requests and leave them in the inflight state.
 *   - Commit last 5 requests to simulate reordering.
 *   - Simulate "crash" and "reconnect".
 *   - Check that all the inflight requests were resubmitted in the
 *     proper order.
 *   - Commit all the requests.
 */
static void inflight_base_test(void)
{
    int res;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);
    /* Number of inflight requests. */
    unsigned num_req = 10;
    /* Number of requests to submit. */
    unsigned num_commit = num_req / 2;

    /* Submit 10 requests and leave them in the inflight state. */
    std::deque<virtio_iov *> iovs;
    std::deque<uint16_t> heads_committed;
    std::deque<uint16_t> heads_inflight;
    std::vector<desc_chain> desc_chain_tbl;
    for (unsigned i = 0; i < num_req; i++) {
        desc_chain_tbl.push_back(desc_chain::indirect_with_buffers({
            {0x00001000, 0x1000},
            {0x00002000, 0x2000},
            {0x00008000, 0x4000},
            {0x0000F000, 0x1000},
        }));
    }
    for (const auto &indir_chain : desc_chain_tbl) {
        uint16_t head = qdata.build_indirect_descriptor_chain(
            indir_chain.buffers, indir_chain.indir_table);
        heads_inflight.push_back(head);
        qdata.publish_avail(head);
        res = qdata.kick_virtq(&vq,
            [&](virtio_iov *iov)
            {
                validate_buffers(indir_chain.buffers, iov);
                iovs.push_back(iov);
            }
        );
        CU_ASSERT(res == 0);
    }
    /* Check that all the submitted requests are in the inflight state. */
    CU_ASSERT(iovs.size() == num_req);
    CU_ASSERT(res == 0);
    CU_ASSERT(heads_inflight.size() == num_req);
    CU_ASSERT(heads_committed.size() == 0);
    validate_inflight_region(qdata, 0);
    validate_inflight_buffers(qdata, heads_inflight, num_req, true);
    validate_inflight_buffers(qdata, heads_committed, 0, false);

    /* Commit last 5 requests to simulate reordering. */
    /* Commit some of the requests in the descending order to simulate reordering. */
    for (unsigned num = 0; num < num_commit && iovs.size(); num++) {
        virtio_iov *iov;
        iov = iovs.back();
        qdata.commit_buffers(&vq, iov, 0);
        iovs.pop_back();

        uint16_t head;
        head = heads_inflight.back();
        heads_inflight.pop_back();
        heads_committed.push_back(head);
    }

    /* Simulate "crash" and "reconnect". */
    virtio_virtq_release(&vq);
    /* Since we are simulating "crash" or disconnect the memory should be
     * clean up.
     */
    for (auto &iov : iovs) {
        virtio_free_iov(iov);
    }
    iovs.clear();

    /* Perform "reconnect". */
    qdata.attach_virtq(&vq);

    /* Check the inflight buffer state after "reconnect". */
    validate_inflight_region(qdata, num_commit);
    validate_inflight_buffers(qdata, heads_inflight, num_req - num_commit,
                              true);
    validate_inflight_buffers(qdata, heads_committed, num_commit, false);

    /* Check that all the inflight requests were resubmitted in the
     * proper order.
     */
    /* Check that the correct order is used to resubmit requests. It is
     * required that resubmission should be made in the ascending counter
     * order.
     */
    uint64_t check_counter = 0;
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            iovs.push_back(iov);
            uint16_t head = virtio_iov_get_head(iov);
            struct inflight_split_desc *idesc = qdata.get_inflight_desc(head);
            /* Check the ascending order. */
            CU_ASSERT(check_counter < idesc->counter);
            check_counter = idesc->counter;
        }
    );
    /* Check that inflight requests were resubmitted. */
    CU_ASSERT(iovs.size() == (num_req - num_commit));
    CU_ASSERT(res == 0);
    /* Check the inflight buffer state, should be the same as after
     * reconnect.
     */
    validate_inflight_region(qdata, num_commit);
    validate_inflight_buffers(qdata, heads_inflight, num_req - num_commit,
                              true);
    validate_inflight_buffers(qdata, heads_committed, num_commit, false);
    CU_ASSERT(res == 0);

    /* Commit all the requests. */
    /* Commit other buffers. */
    for (const auto &iov : iovs) {
        qdata.commit_buffers(&vq, iov, 0);
    }
    while (heads_inflight.size()) {
        uint16_t head = heads_inflight.front();
        heads_inflight.pop_front();
        heads_committed.push_back(head);
    }
    /* Check that there is no inflight requests. */
    validate_inflight_region(qdata, num_req);
    validate_inflight_buffers(qdata, heads_inflight, 0, true);
    validate_inflight_buffers(qdata, heads_committed, num_req, false);

    virtio_virtq_release(&vq);

    return;
}

/* This is the main test for the inflight/reconnect functionality.
 * The general steps are as follows:
 *   - Submit requests and leave them in the inflight state.
 *   - Commit several last requests to simulate reordering.
 *   - Make the inflight memory region inconsistent.
 *   - Simulate "crash" and "reconnect".
 *   - Check that memory region is recovered.
 *   - Check that all the inflight requests were resubmitted in the
 *     proper order.
 *   - Commit all the requests.
 */
static void inflight_recover_test(void)
{
    int res;
    queue_data qdata;

    virtio_virtq vq;
    qdata.attach_virtq(&vq);
    /* Number of inflight requests. */
    unsigned num_req = 10;
    /* Number of requests to submit. */
    unsigned num_commit = 6;

    /* Submit requests and leave them in the inflight state. */
    std::deque<virtio_iov *> iovs;
    std::deque<uint16_t> heads_committed;
    std::deque<uint16_t> heads_inflight;
    std::vector<desc_chain> desc_chain_tbl;
    for (unsigned i = 0; i < num_req; i++) {
        desc_chain_tbl.push_back(desc_chain::indirect_with_buffers({
            {0x00001000, 0x1000},
            {0x00002000, 0x2000},
            {0x00008000, 0x4000},
            {0x0000F000, 0x1000},
        }));
    }
    for (const auto &indir_chain : desc_chain_tbl) {
        uint16_t head = qdata.build_indirect_descriptor_chain(
            indir_chain.buffers, indir_chain.indir_table);
        heads_inflight.push_back(head);
        qdata.publish_avail(head);
        res = qdata.kick_virtq(&vq,
            [&](virtio_iov *iov)
            {
                validate_buffers(indir_chain.buffers, iov);
                iovs.push_back(iov);
            }
        );
        CU_ASSERT(res == 0);
    }
    /* Check that all the submitted requests are in the inflight state. */
    CU_ASSERT(iovs.size() == num_req);
    CU_ASSERT(res == 0);
    CU_ASSERT(heads_inflight.size() == num_req);
    CU_ASSERT(heads_committed.size() == 0);
    validate_inflight_region(qdata, 0);
    validate_inflight_buffers(qdata, heads_inflight, num_req, true);
    validate_inflight_buffers(qdata, heads_committed, 0, false);

    /* Commit several last requests to simulate reordering. */
    /* Commit some of the requests in the descending order to simulate reordering. */
    for (unsigned num = 0; num < num_commit && iovs.size(); num++) {
        virtio_iov *iov;
        iov = iovs.back();
        qdata.commit_buffers(&vq, iov, 0);
        iovs.pop_back();

        uint16_t head;
        head = heads_inflight.back();
        heads_inflight.pop_back();
        heads_committed.push_back(head);
    }

    /* Make the inflight memory region inconsistent. */
    /* Simulate disconnect in virtq_commit_buffers() after
     *   vq->used->idx++;
     * disconnect before:
     *   virtq_inflight_used_commit(vq, used->id);
     * To do it, let's revert the changes in the inflight buffer.
     *   vq->inflight_region->desc[head].inflight = 0;
     *   vq->inflight_region->used_idx = vq->used->idx;
     */
    struct inflight_split_region *ireg = qdata.get_inflight_region();
    struct inflight_split_desc *idesc =
        qdata.get_inflight_desc(heads_committed.back());
    idesc->inflight = 1;
    uint16_t recover_idx = ireg->used_idx;
    ireg->used_idx--;

    /* Simulate "crash" and "reconnect". */
    virtio_virtq_release(&vq);
    /* Since we are simulating "crash" or disconnect the memory should be
     * clean up.
     */
    for (auto &iov : iovs) {
        virtio_free_iov(iov);
    }
    iovs.clear();

    /* Perform "reconnect". */
    qdata.attach_virtq(&vq);
    /* The inflight region should be fixed after attach. */
    CU_ASSERT(ireg->used_idx == recover_idx);
    CU_ASSERT(idesc->inflight == 0);

    /* Check the inflight buffer state after "reconnect". */
    validate_inflight_region(qdata, num_commit);
    validate_inflight_buffers(qdata, heads_inflight, num_req - num_commit,
                              true);
    validate_inflight_buffers(qdata, heads_committed, num_commit, false);

    /* Check that all the inflight requests were resubmitted in the
     * proper order.
     */
    /* Check that the correct order is used to resubmit requests. It is
     * required that resubmission should be made in the ascending counter
     * order.
     */
    uint64_t check_counter = 0;
    res = qdata.kick_virtq(&vq,
        [&](virtio_iov *iov)
        {
            iovs.push_back(iov);
            uint16_t head = virtio_iov_get_head(iov);
            struct inflight_split_desc *idesc = qdata.get_inflight_desc(head);
            /* Check the ascending order. */
            CU_ASSERT(check_counter < idesc->counter);
            check_counter = idesc->counter;
        }
    );
    /* Check that inflight requests were resubmitted. */
    CU_ASSERT(iovs.size() == (num_req - num_commit));
    CU_ASSERT(res == 0);
    /* Check the inflight buffer state, should be the same as after
     * reconnect.
     */
    validate_inflight_region(qdata, num_commit);
    validate_inflight_buffers(qdata, heads_inflight, num_req - num_commit,
                              true);
    validate_inflight_buffers(qdata, heads_committed, num_commit, false);
    CU_ASSERT(res == 0);

    /* Commit all the requests. */
    /* Commit other buffers. */
    for (const auto &iov : iovs) {
        qdata.commit_buffers(&vq, iov, 0);
    }
    while (heads_inflight.size()) {
        uint16_t head = heads_inflight.front();
        heads_inflight.pop_front();
        heads_committed.push_back(head);
    }
    /* Check that there is no inflight requests. */
    validate_inflight_region(qdata, num_req);
    validate_inflight_buffers(qdata, heads_inflight, 0, true);
    validate_inflight_buffers(qdata, heads_committed, num_req, false);

    virtio_virtq_release(&vq);

    return;
}

int main(void)
{
    int res = 0;
    CU_pSuite suite = NULL;

    g_log_fn = vhd_log_stderr;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    suite = CU_add_suite("virtq_test", NULL, NULL);
    if (NULL == suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_ADD_TEST(suite, direct_descriptors_test);
    CU_ADD_TEST(suite, indirect_descriptors_test);
    CU_ADD_TEST(suite, mixed_descriptors_test);
    CU_ADD_TEST(suite, combined_descriptor_chain_test);
    CU_ADD_TEST(suite, oob_descriptor_test);
    CU_ADD_TEST(suite, indirect_oob_descriptor_test);
    CU_ADD_TEST(suite, descriptor_loop_test);
    CU_ADD_TEST(suite, indirect_descriptor_loop_test);
    CU_ADD_TEST(suite, bad_indirect_descriptor_test);
    CU_ADD_TEST(suite, bad_indirect_descriptor_table_size_test);
    CU_ADD_TEST(suite, broken_queue_test);
    CU_ADD_TEST(suite, inflight_base_test);
    CU_ADD_TEST(suite, inflight_recover_test);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    res = CU_get_error() || CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    return res;
}
