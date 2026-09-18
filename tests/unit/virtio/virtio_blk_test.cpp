#include <string>
#include <vector>
#include <queue>
#include <memory>

#include <CUnit/Basic.h>

#include "vhost/blockdev.h"
#include "bio.h"
#include "vdev.h"

#include "virtio/virtio_blk.h"
#include "virtio/virtio_blk_spec.h"

#include "qdata.h"

#include "memmap.h"
#include "logging.h"
#include "../test_utils.h"

using namespace virtio_test;

// virtio memory mapper mock
extern "C" {
void *gpa_range_to_ptr(struct vhd_memory_map *, uint64_t gpa, size_t)
{
    return (void *)gpa;
}

void vhd_memmap_ref(struct vhd_memory_map *)
{
}

void vhd_memmap_unref(struct vhd_memory_map *)
{
}

/* Strong definition to really mark queue broken not just emit warning */
void abort_request(struct virtio_virtq *vq, struct virtio_iov *iov)
{
    /*
     * FIXME: this is called when the message framing is messed up.  This
     * appears severe enough to just stop processing the virtq and mark it
     * broken
     */
    VHD_LOG_ERROR("no valid virtio request found, aborting queue %p", vq);
    virtq_push(vq, iov, 0);
    virtio_free_iov(iov);
    mark_broken(vq);
}

}

static constexpr uint64_t default_block_size = 4096;
static constexpr uint64_t default_block_count = 256;
static const char *default_disk_id = "01234567899876543210"; // Make sure it is 20 symbols

struct bdev_request {
    virtio_blk_req_hdr hdr{};
    std::vector<std::vector<uint8_t> *> buffers;
    uint8_t status;

    std::vector<q_iovec> iovecs;

    bdev_request(const std::vector<std::vector<uint8_t> *> &_buffers,
                 iodir data_dir)
        : buffers(_buffers), status(0)
    {
        iovecs.emplace_back(&hdr, sizeof(hdr), iodir::device_read);
        for (const auto *buf : buffers) {
            iovecs.emplace_back((void *)buf->data(), buf->size(), data_dir);
        }
        iovecs.emplace_back(&status, sizeof(status), iodir::device_write);
    }

    bdev_request(const std::vector<uint8_t> &discard_or_write_zeroes_seg)
    {
        iovecs.emplace_back(&hdr, sizeof(hdr), iodir::device_read);
        iovecs.emplace_back((void *)discard_or_write_zeroes_seg.data(),
                            discard_or_write_zeroes_seg.size(),
                            iodir::device_read);
        iovecs.emplace_back(&status, sizeof(status), iodir::device_write);
    }

    static std::shared_ptr<bdev_request> make_io(
        iodir dir,
        uint64_t sector,
        const std::vector<std::vector<uint8_t> *> &buffers)
    {
        auto req = std::make_shared<bdev_request>(buffers, dir);
        req->hdr.type =
            (dir == iodir::req_read ? VIRTIO_BLK_T_IN : VIRTIO_BLK_T_OUT);
        req->hdr.sector = sector;
        return req;
    }

    static std::shared_ptr<bdev_request> make_discard(
        const std::vector<uint8_t> &segment
    )
    {
        auto req = std::make_shared<bdev_request>(segment);
        req->hdr.type = VIRTIO_BLK_T_DISCARD;
        return req;
    }

    static std::shared_ptr<bdev_request> make_write_zeroes(
        const std::vector<uint8_t> &segment
    )
    {
        auto req = std::make_shared<bdev_request>(segment);
        req->hdr.type = VIRTIO_BLK_T_WRITE_ZEROES;
        return req;
    }

    static std::shared_ptr<bdev_request> make_getid(std::vector<uint8_t> *idbuf)
    {
        auto req = std::make_shared<bdev_request>(
            std::vector<std::vector<uint8_t> *>{idbuf}, iodir::device_write);
        req->hdr.type = VIRTIO_BLK_T_GET_ID;
        return req;
    }

    bool is_io() const
    {
        return hdr.type == VIRTIO_BLK_T_IN || hdr.type == VIRTIO_BLK_T_OUT ||
               hdr.type == VIRTIO_BLK_T_DISCARD ||
               hdr.type == VIRTIO_BLK_T_WRITE_ZEROES;
    }

    uint64_t sector() const
    {
        if (hdr.type == VIRTIO_BLK_T_DISCARD ||
            hdr.type == VIRTIO_BLK_T_WRITE_ZEROES) {
            virtio_blk_discard_write_zeroes seg;
            memcpy(&seg, iovecs[1].addr, sizeof(seg));
            return seg.sector;
        }

        return hdr.sector;
    }

    uint64_t total_sectors() const
    {
        if (hdr.type == VIRTIO_BLK_T_IN || hdr.type == VIRTIO_BLK_T_OUT) {
            uint64_t total = 0;
            for (const auto *buf : buffers) {
                total += buf->size() / 512;
            }
            return total;
        }

        virtio_blk_discard_write_zeroes seg;
        memcpy(&seg, iovecs[1].addr, sizeof(seg));
        return seg.num_sectors;
    }
};

struct test_bdev {
    /* Must be first */
    virtio_blk_dev vdev{};

    vhd_bdev_info bdev{};

    queue_data qdata;
    virtio_virtq vq{};

    std::string disk_id;

    std::queue<std::shared_ptr<bdev_request>> requests;
    std::queue<std::shared_ptr<bdev_request>> completed_requests;

    std::vector<uint8_t> blocks;

    test_bdev(uint64_t block_size, uint64_t total_blocks, const char *id,
              bool has_discard, bool has_write_zeroes) :
        disk_id(id), blocks(block_size * total_blocks, 0xAA)
    {
        qdata.attach_virtq(&vq);

        bdev.serial = disk_id.c_str();
        bdev.block_size = block_size;
        bdev.total_blocks = total_blocks;
        bdev.num_queues = 1;

        if (has_discard) {
            bdev.features |= VHD_BDEV_F_DISCARD;
        }
        if (has_write_zeroes) {
            bdev.features |= VHD_BDEV_F_WRITE_ZEROES;
        }

        virtio_blk_init_dev(&vdev, &bdev);
    }

    test_bdev() : test_bdev(default_block_size, default_block_count,
                            default_disk_id, true, true) {}

    ~test_bdev()
    {
        virtio_virtq_release(&vq);
        virtio_blk_destroy_dev(&vdev);
    }

    uint64_t block_size() const
    {
        return bdev.block_size;
    }

    uint64_t total_blocks() const
    {
        return bdev.total_blocks;
    }

    uint64_t total_sectors() const
    {
        return bdev.total_blocks * bdev.block_size / 512;
    }

    uint64_t sectors_to_blocks(uint64_t sectors) const
    {
        uint64_t res = sectors * 512 / bdev.block_size;
        CU_ASSERT_FATAL(res * bdev.block_size / 512 == sectors);
        return res;
    }

    uint64_t blocks_to_sectors(uint64_t num_blocks) const
    {
        uint64_t res = num_blocks * bdev.block_size / 512;
        CU_ASSERT_FATAL(res * 512 / bdev.block_size == num_blocks);
        return res;
    }

    void set_block(uint64_t block, uint8_t data)
    {
        memset(get_block(block), data, bdev.block_size);
    }

    uint8_t *get_block(uint64_t block)
    {
        CU_ASSERT_FATAL(block < bdev.total_blocks);
        return blocks.data() + (block * bdev.block_size);
    }

    void handle_io(struct vhd_io *io)
    {
        struct vhd_bdev_io *bio = vhd_get_bdev_io(io);
        vhd_buffer *pbuf;
        uint64_t block, rem_blocks;

        std::shared_ptr<bdev_request> req = requests.front();

        CU_ASSERT(req->sector() == bio->first_sector);
        CU_ASSERT(req->total_sectors() == bio->total_sectors);

        /*
         * NOTE: we don't actually zero out the sectors here because we
         *       don't need to for the purposes of this test suite and
         *       nothing actually verifies it or looks at the data.
         */
        if (bio->type == VHD_BDEV_DISCARD ||
            bio->type == VHD_BDEV_WRITE_ZEROES) {
            goto complete_req;
        }

        pbuf = bio->sglist.buffers;
        block = sectors_to_blocks(bio->first_sector);
        rem_blocks = sectors_to_blocks(bio->total_sectors);

        for (size_t i = 0; i < bio->sglist.nbuffers; ++i) {
            CU_ASSERT(pbuf->len != 0 &&
                      ((pbuf->len & (bdev.block_size - 1)) == 0));

            uint64_t num_blocks = pbuf->len / bdev.block_size;
            CU_ASSERT(num_blocks <= rem_blocks);

            if (bio->type == VHD_BDEV_READ) {
                memcpy(pbuf->base, get_block(block), pbuf->len);
            } else if (bio->type == VHD_BDEV_WRITE) {
                memcpy(get_block(block), pbuf->base, pbuf->len);
            } else {
                CU_ASSERT(0);
            }

            block += num_blocks;
            rem_blocks -= num_blocks;
            pbuf++;
        }

        CU_ASSERT(rem_blocks == 0);

    complete_req:
        io->status = VHD_BDEV_SUCCESS;
        io->completion_handler(io);

        requests.pop();
        completed_requests.push(req);
    }

    void execute_request(const std::vector<q_iovec> &iovecs)
    {
        uint16_t head = qdata.build_descriptor_chain(iovecs);
        size_t bytes_to_write = 0;
        for (auto &iovec: iovecs) {
            if (iovec.dir == iodir::device_write)
                bytes_to_write += iovec.len;
        }
        qdata.publish_avail(head);

        CU_ASSERT(virtio_blk_dispatch_requests(&vdev, &vq) == 0);

        // vblk backend should have disposed of buffers in any case
        auto used = qdata.collect_used();
        CU_ASSERT(!used.empty());
        CU_ASSERT(used.front().id == head);
        CU_ASSERT(used.front().len == (vq.broken ? 0 : bytes_to_write));
    }

    uint8_t execute_request_io(const std::shared_ptr<bdev_request>& req)
    {
        requests.push(req);

        execute_request(req->iovecs);

        if (req->status != VIRTIO_BLK_S_OK) {
            /* Request should not have been completed on error */
            CU_ASSERT(completed_requests.empty());
            requests.pop();
            return req->status;
        }

        if (completed_requests.empty()) {
            /* Something went wrong and handle_io was not called, but status
               was not set to error */
            CU_ASSERT(req->status != VIRTIO_BLK_S_OK);
            requests.pop();
            return req->status;
        }

        CU_ASSERT(requests.empty());
        CU_ASSERT(req == completed_requests.front());
        completed_requests.pop();

        return req->status;
    }

    uint8_t execute_request_nocb(const std::shared_ptr<bdev_request>& req)
    {
        execute_request(req->iovecs);
        return req->status;
    }

    uint8_t execute_request(const std::shared_ptr<bdev_request>& req)
    {
        if (req->is_io()) {
            return execute_request_io(req);
        } else {
            return execute_request_nocb(req);
        }
    }

    void reset_broken() {
        CU_ASSERT(vq.broken);
        vq.broken = false;
    }
};

int virtio_blk_handle_request(struct virtio_virtq *vq, struct vhd_io *io)
{
    // Dummy vring - used to prevent NULL pointer dereference
    // in complete_io() when it accesses io->vring->vdev
    static struct vhd_vring dummy_vring = {
        .vdev = NULL,
    };
    io->vring = &dummy_vring;

    test_bdev *self = containerof(vq, test_bdev, vq);
    self->handle_io(io);
    return 0;
}

static void validate_buffer(const uint8_t *buf, size_t nsectors,
                            uint8_t pattern)
{
    uint8_t sector[VIRTIO_BLK_SECTOR_SIZE];
    memset(sector, pattern, sizeof(sector));

    for (size_t i = 0; i < nsectors; ++i) {
        if (0 != memcmp(sector, buf + i * sizeof(sector), sizeof(sector))) {
            CU_ASSERT(false);
            break;
        }
    }

    CU_ASSERT(true);
}

////////////////////////////////////////////////////////////////////////////////

static uint8_t execute_discard_or_write_zeroes(
        test_bdev& bdev, uint64_t first_block,
        uint64_t total_blocks, bool is_discard)
{
    virtio_blk_discard_write_zeroes seg {};
    std::vector<uint8_t> seg_data(sizeof(seg));
    std::shared_ptr<bdev_request> req;

    seg.sector = first_block;
    seg.num_sectors = total_blocks;
    memcpy(seg_data.data(), &seg, sizeof(seg));

    if (is_discard) {
        req = bdev_request::make_discard(seg_data);
    } else {
        req = bdev_request::make_write_zeroes(seg_data);
    }

    return bdev.execute_request(req);
}

static void io_requests_test()
{
    uint8_t status;
    test_bdev bdev;

    // Set disk pattern
    for (uint64_t block = 0; block < bdev.total_blocks(); ++block) {
        bdev.set_block(block, 0xAF);
    }

    // Read entire disk
    {
        std::vector<uint8_t> buf(bdev.total_blocks() * bdev.block_size(), 0);
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);

        validate_buffer(buf.data(), bdev.total_sectors(), 0xAF);
    }

    // Write some blocks in the middle
    uint64_t first_block = 16;
    uint64_t total_blocks = 16;
    {
        std::vector<uint8_t> buf(bdev.block_size() * total_blocks, 0);
        auto req = bdev_request::make_io(
                iodir::req_write,
                bdev.blocks_to_sectors(first_block),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);
    }

    // Read entire disk again and validate write
    {
        std::vector<uint8_t> buf(bdev.total_blocks() * bdev.block_size(), 0);
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);

        uint8_t *pdata = buf.data();

        validate_buffer(pdata, bdev.blocks_to_sectors(first_block), 0xAF);
        pdata += first_block * bdev.block_size();

        validate_buffer(pdata, bdev.blocks_to_sectors(total_blocks), 0);
        pdata += total_blocks * bdev.block_size();

        validate_buffer(pdata,
            bdev.blocks_to_sectors(bdev.total_blocks() - total_blocks - first_block),
            0xAF);
    }

    // Do a discard
    status = execute_discard_or_write_zeroes(bdev, first_block, total_blocks,
                                             true);
    CU_ASSERT(status == VIRTIO_BLK_S_OK);

    // Write zeroes
    status = execute_discard_or_write_zeroes(bdev, first_block, total_blocks,
                                             false);
    CU_ASSERT(status == VIRTIO_BLK_S_OK);
}

static void multibuffer_io_test()
{
    uint8_t status;
    test_bdev bdev;

    // Set disk pattern
    for (uint64_t block = 0; block < bdev.total_blocks(); ++block) {
        bdev.set_block(block, 0xAF);
    }

    std::vector<std::vector<uint8_t> *> buffers;
    buffers.reserve(bdev.total_blocks());
    for (uint64_t i = 0; i < bdev.total_blocks(); ++i) {
        buffers.push_back(new std::vector<uint8_t>(bdev.block_size(), 0));
    }

    // Write entire disk, use 1 buffer per block
    {
        // Fill block data with block number
        for (uint64_t i = 0; i < bdev.total_blocks(); ++i) {
            memset(buffers[i]->data(), (uint8_t)i, bdev.block_size());
        }

        auto req = bdev_request::make_io(
                iodir::req_write,
                0,
                buffers);

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);
    }

    // Read entire disk, use 1 buffer per block, and validate write
    {
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                buffers);

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);

        for (uint64_t i = 0; i < bdev.total_blocks(); ++i) {
            validate_buffer(buffers[i]->data(), bdev.block_size() / 512,
                            (uint8_t)i);
        }
    }

    // Read entire disk, use 1 buffer per block, but 1 last buffer is not writable by device
    {
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                buffers);

        for (uint64_t i = 0; i < bdev.total_blocks(); ++i) {
            req->iovecs[i + 1].dir = iodir::device_read;
        }

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_IOERR);
    }

    for (std::vector<uint8_t> *buf : buffers) {
        delete buf;
    }
}

static void empty_request_test()
{
    uint8_t status;
    test_bdev bdev;

    // Set disk pattern
    for (uint64_t block = 0; block < bdev.total_blocks(); ++block) {
        bdev.set_block(block, 0xAF);
    }

    std::vector<uint8_t> zerobuf;
    zerobuf.reserve(512); // reserve makes data() pointer not be NULL

    // Read 0 sectors
    {
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                std::vector<std::vector<uint8_t> *>{&zerobuf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);
    }

    // Write 0 sectors
    {
        auto req = bdev_request::make_io(
                iodir::req_write,
                0,
                std::vector<std::vector<uint8_t> *>{&zerobuf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);
    }

    // Read whole disk and make sure nothing changed due to 0-sized write
    {
        std::vector<uint8_t> buf(bdev.total_blocks() * bdev.block_size(), 0);
        auto req = bdev_request::make_io(
                iodir::req_read,
                0,
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);

        validate_buffer(buf.data(), bdev.total_sectors(), 0xAF);
    }
}

static void oob_request_test()
{
    uint8_t status;
    test_bdev bdev;

    // OOB start sector read/write
    {
        std::vector<uint8_t> buf(bdev.block_size(), 0);
        std::shared_ptr<bdev_request> req;

        req = bdev_request::make_io(
                iodir::req_read,
                bdev.total_sectors(),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);

        req = bdev_request::make_io(
                iodir::req_write,
                bdev.total_sectors(),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);
    }

    // OOB on last block in range read/write
    {
        // Mark last block
        bdev.set_block(bdev.total_blocks() - 1, 0xAF);

        std::vector<uint8_t> buf(bdev.block_size() * 2, 0);
        std::shared_ptr<bdev_request> req;

        req = bdev_request::make_io(
                iodir::req_read,
                bdev.blocks_to_sectors(bdev.total_blocks() - 1),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);

        req = bdev_request::make_io(
                iodir::req_write,
                bdev.blocks_to_sectors(bdev.total_blocks() - 1),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status != VIRTIO_BLK_S_OK);

        // Last sector shouldn't have changed
        buf.resize(bdev.block_size());
        req = bdev_request::make_io(
                iodir::req_read,
                bdev.blocks_to_sectors(bdev.total_blocks() - 1),
                std::vector<std::vector<uint8_t> *>{&buf});

        status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);

        validate_buffer(buf.data(), bdev.blocks_to_sectors(1), 0xAF);
    }

    // OOB discard request
    status = execute_discard_or_write_zeroes(
            bdev, bdev.blocks_to_sectors(bdev.total_blocks()), 1, true);
    CU_ASSERT(status != VIRTIO_BLK_S_OK);

    // OOB write-zeroes request
    status = execute_discard_or_write_zeroes(
            bdev, bdev.blocks_to_sectors(bdev.total_blocks()), 1, false);
    CU_ASSERT(status != VIRTIO_BLK_S_OK);
}

static void bad_request_layout_test()
{
    test_bdev bdev;
    std::vector<uint8_t> buf(bdev.block_size(), 0);
    virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_IN };

    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr)},
            // No data buffer
            {&status, sizeof(status)},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr)},
            {buf.data(), buf.size()},
            {&status, 0}, // Wrong status field size
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr) - 1}, // Wrong header field size
            {buf.data(), buf.size()},
            {&status, sizeof(status)},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr)},
            // Missing status and data fields
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }
}

static void bad_iodir_test()
{
    test_bdev bdev;
    std::vector<uint8_t> buf(bdev.block_size(), 0);

    // No read capability on request header buffer
    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_OUT }; // request type does not matter

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_write}, // Header buffer is not readable
            {buf.data(), buf.size(), iodir::device_write},
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    // No write capability on status buffer on IO request
    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_OUT }; // request type does not matter

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {buf.data(), buf.size(), iodir::device_read},
            {&status, sizeof(status), iodir::device_read}, // Status buffer is not writable
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    // Read request without proper write capability
    {
        uint8_t status = 0;
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_IN };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {buf.data(), buf.size(), iodir::device_read}, // No device write capability on buffer
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == VIRTIO_BLK_S_IOERR);
    }

    // Write request without proper read capability
    {
        uint8_t status = 0;
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_OUT };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {buf.data(), buf.size(), iodir::device_write}, // No device read capability on buffer
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == VIRTIO_BLK_S_IOERR);
    }
}

static void getid_test()
{
    test_bdev bdev;

    std::vector<uint8_t> idbuf(VIRTIO_BLK_DISKID_LENGTH);

    // Successfull getid
    {
        auto req = bdev_request::make_getid(&idbuf);

        uint8_t status = bdev.execute_request(req);
        CU_ASSERT(status == VIRTIO_BLK_S_OK);
        CU_ASSERT(0 == strncmp((char *)idbuf.data(), default_disk_id,
                               VIRTIO_BLK_DISKID_LENGTH));
    }

    // header buffer is not readable
    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_GET_ID };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_write}, // Header buffer is not readable
            {idbuf.data(), idbuf.size(), iodir::device_write},
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    // status buffer is not writable
    {
        uint8_t status = 0xAF; // Poison status to make sure it is not touched
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_GET_ID };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {idbuf.data(), idbuf.size(), iodir::device_read},
            {&status, sizeof(status), iodir::device_read}, // Status buffer is not writable
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == 0xAF);
        bdev.reset_broken();
    }

    // id buffer is not writable
    {
        uint8_t status = 0;
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_GET_ID };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {idbuf.data(), idbuf.size(), iodir::device_read}, // Id buffer is not writable
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == VIRTIO_BLK_S_IOERR);
    }

    // id buffer wrong size
    {
        uint8_t status = 0;
        virtio_blk_req_hdr hdr = { .type = VIRTIO_BLK_T_GET_ID };

        std::vector<q_iovec> buffers {
            {&hdr, sizeof(hdr), iodir::device_read},
            {idbuf.data(), idbuf.size() - 1, iodir::device_write},
            {&status, sizeof(status), iodir::device_write},
        };

        bdev.execute_request(buffers);
        CU_ASSERT(status == VIRTIO_BLK_S_IOERR);
    }
}

static void discard_no_discard_support_test()
{
    test_bdev bdev(default_block_size, default_block_count,
                   default_disk_id, false, true);

    // Discard request on a bdev without DISCARD support
    auto status = execute_discard_or_write_zeroes(bdev, 0, 1, true);
    CU_ASSERT(status == VIRTIO_BLK_S_UNSUPP);
}

static void write_zeroes_no_write_zeroes_support_test()
{
    test_bdev bdev(default_block_size, default_block_count,
                   default_disk_id, true, false);

    // Write-zeroes request on a bdev without WRITE_ZEROES support
    auto status = execute_discard_or_write_zeroes(bdev, 0, 1, false);
    CU_ASSERT(status == VIRTIO_BLK_S_UNSUPP);
}

int main()
{
    int res;
    CU_pSuite suite;

    g_log_fn = vhd_log_stderr;

    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    suite = CU_add_suite("virtio_blk_test", nullptr, nullptr);
    if (nullptr == suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_ADD_TEST(suite, io_requests_test);
    CU_ADD_TEST(suite, multibuffer_io_test);
    CU_ADD_TEST(suite, empty_request_test);
    CU_ADD_TEST(suite, oob_request_test);
    CU_ADD_TEST(suite, bad_request_layout_test);
    CU_ADD_TEST(suite, bad_iodir_test);
    CU_ADD_TEST(suite, getid_test);
    CU_ADD_TEST(suite, discard_no_discard_support_test);
    CU_ADD_TEST(suite, write_zeroes_no_write_zeroes_support_test);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    res = CU_get_error() || CU_get_number_of_tests_failed();
    CU_cleanup_registry();

    return res;
}
