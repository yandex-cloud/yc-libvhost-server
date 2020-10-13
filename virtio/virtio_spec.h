/**
 * Definitions from virtio spec version 1.0
 * http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html.
 *
 * Type naming and style is preserved verbatim from virtio spec.
 */

#pragma once

#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRTQ_SIZE_MAX  32768u
#define VIRTQ_ALIGNMENT PAGE_SIZE
#define VIRTQ_ALIGN(x)  (((x) + VIRTQ_ALIGNMENT) & ~VIRTQ_ALIGNMENT)

struct virtq_desc {
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;

    /* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT       1
    /* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE      2
    /* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT   4
    /* The flags as indicated above. */
    uint16_t flags;
    /* Next field if flags & NEXT */
    uint16_t next;
};
VHD_STATIC_ASSERT(sizeof(struct virtq_desc) == 16);

struct virtq_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT      1
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[]; /* Queue Size */
};
VHD_STATIC_ASSERT(sizeof(struct virtq_avail) == 4);

/* le32 is used here for ids for padding reasons. */
struct virtq_used_elem {
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was used (written to) */
    uint32_t len;
};
VHD_STATIC_ASSERT(sizeof(struct virtq_used_elem) == 8);

struct virtq_used {
#define VIRTQ_USED_F_NO_NOTIFY  1
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[]; /* Queue Size */
};
VHD_STATIC_ASSERT(sizeof(struct virtq_used) == 4);

/*
 * Virtqueue layout cannot be represented by a C struct,
 * definition below is intentionally a comment.
struct virtq {
    // The actual descriptors (16 bytes each)
    struct virtq_desc desc[ Queue Size ];

    // A ring of available descriptor heads with free-running index.
    struct virtq_avail avail;
    uint16_t used_event; // Only if VIRTIO_F_EVENT_IDX

    // Padding to the next PAGE_SIZE boundary.
    uint8_t pad[ Padding ];

    // A ring of used descriptor heads with free-running index.
    struct virtq_used used;
    le16 avail_event; // Only if VIRTIO_F_EVENT_IDX
};
*/

static inline unsigned virtq_size(unsigned int qsz)
{
    return VIRTQ_ALIGN(sizeof(struct virtq_desc) * qsz + sizeof(uint16_t) * (3 + qsz))
        + VIRTQ_ALIGN(sizeof(uint16_t) * 3 + sizeof(struct virtq_used_elem) * qsz);
}

#ifdef __cplusplus
}
#endif
