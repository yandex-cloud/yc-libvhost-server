/**
 * Fault injection for vhost-user requests.
 *
 * Only meant for testing how a client copes with a misbehaving backend, so
 * it's only compiled into the library if VHD_FAULT_INJECTION is defined, see
 * the fault-injection meson option.
 */

#pragma once

#ifndef VHD_FAULT_INJECTION
#error "VHD_FAULT_INJECTION is not defined"
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vhd_vdev;

/**
 * A fault to inject upon receiving a vhost-user request, instead of handling
 * it.
 */
enum vhd_msg_fault {
    VHD_MSG_FAULT_NONE = 0,

    /* Abort the process, as if the backend has crashed */
    VHD_MSG_FAULT_ABORT,

    /*
     * Fail the request the way the protocol allows it: with a negative
     * acknowledgement if the client has asked for one, by dropping the
     * connection otherwise
     */
    VHD_MSG_FAULT_FAIL,
};

/**
 * Inject @fault each time @vdev receives the vhost-user request @req, until
 * reset by setting VHD_MSG_FAULT_NONE.
 */
int vhd_vdev_set_msg_fault(struct vhd_vdev *vdev, uint32_t req,
                           enum vhd_msg_fault fault);

#ifdef __cplusplus
}
#endif
