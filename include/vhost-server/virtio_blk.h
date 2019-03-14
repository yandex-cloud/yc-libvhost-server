#ifndef _VHD_VIRTIO_BLK_H
#define _VHD_VIRTIO_BLK_H

#include <stdint.h>

/* This is the default sector size for the block virtio request. */
#define BLK_SECTOR_SIZE     512
#define BLK_SECTOR_SIZE_EXP 9

#define BLK_DISKID_LENGTH 20
#define BLK_STATUS_LENGTH 1

/* Virtual queue block device features (GET_FEATURES and SET_FEATURES
 * commands.
 */
#define VIRTIO_BLK_F_BARRIER    0
#define VIRTIO_BLK_F_SIZE_MAX   1
#define VIRTIO_BLK_F_SEG_MAX    2
#define VIRTIO_BLK_F_GEOMETRY   4
#define VIRTIO_BLK_F_RO         5
#define VIRTIO_BLK_F_BLK_SIZE   6
#define VIRTIO_BLK_F_SCSI       7
#define VIRTIO_BLK_F_FLUSH      9
#define VIRTIO_BLK_F_TOPOLOGY   10
#define VIRTIO_BLK_F_CONFIG_WCE 11
#define VIRTIO_BLK_F_MQ         12

enum {
    VIRTIO_BLK_T_IN = 0,
    VIRTIO_BLK_T_OUT = 1,
    VIRTIO_BLK_T_SCSI_CMD = 2,
    VIRTIO_BLK_T_SCSI_CMD_OUT = 3,
    VIRTIO_BLK_T_FLUSH = 4,
    VIRTIO_BLK_T_FLUSH_OUT = 5,
    VIRTIO_BLK_T_GET_ID = 8,
    VIRTIO_BLK_T_BARRIER = 0x80000000,
};

enum {
    VIRTIO_BLK_S_OK = 0,
    VIRTIO_BLK_S_IOERR = 1,
    VIRTIO_BLK_S_UNSUPP = 2,
};

struct TVirtioBlkReq {
    uint32_t Type;
    uint32_t Reserved;
    uint64_t Sector;
} __attribute__((packed));

/* Response for the VHOST_USER_GET_CONFIG command. */
struct TVirtioBlkConfig {
    uint64_t Capacity;
    uint32_t SizeMax;
    uint32_t SegMax;

    /* geometry */
    uint16_t Cylinders;
    uint8_t Heads;
    uint8_t Sectors;

    uint32_t BlkSize;

    /* topology */
    uint8_t PhysicalBlockExp;
    uint8_t AlignmentOffset;
    uint16_t MinIoSize;
    uint32_t OptIoSize;

    uint8_t Writeback;
    uint8_t Reserved;
    uint16_t NumQueues;
} __attribute__((packed));

struct TVirtioBlkMem {
    uint32_t BlkSize;
    uint32_t BlkSizeExp;
    int Num;
    /* Address to the request buffer. */
    struct TVirtioBlkReq* Reqs;
    /* Address to the status. */
    uint8_t* Status;
    /* Address to the buffers for IO. */
    uint8_t* BufferCur;
    uint8_t* BufferStart;
    uint8_t* BufferEnd;
    /* Current free index to use. */
    uint32_t FreeIdx;
};

void *BlkVirtQueue(void *arg);

/* TODO: This is just the rough block device emulation. Will be
 * changed to the device backend.
 */
int FileBlockDevOpen(const char *path, uint64_t nBlocks);
int FileBlockDevGetBlkSize();
int FileBlockDevGetBlkNum();
int FileBlockDevRead(uint64_t offset, void *buf, uint64_t len);
int FileBlockDevWrite(uint64_t offset, void *buf, uint64_t len);

#endif /* _VHD_VIRTIO_BLK_H */
