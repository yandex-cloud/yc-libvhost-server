/*
 * Lists and queues.
 *
 * Relevant OSes provide BSD-originated sys/queue.h, so just use it here, with
 * a few extensions.
 */

#pragma once

#include <sys/queue.h>

/*
 * Atomic extensions (based on QEMU qemu/queue.h) necessary for bottom halves
 * implementation
 */
#include "catomic.h"

/*
 * Cater to the strict _Atomic-qual checking of clang and define a version of
 * SLIST_HEAD usable with the below atomic ops.  Aside from the _Atomic
 * qualifier it's identical to the original SLIST_HEAD, so all other SLIST_*
 * ops work fine on it.
 */
#define SLIST_HEAD_ATOMIC(name, type)                           \
    struct name {                                               \
        struct type *_Atomic slh_first; /* first element */     \
    }

#define SLIST_INSERT_HEAD_ATOMIC(head, elm, field)      ({               \
    typeof(elm) old_slh_first;                                           \
    do {                                                                 \
        old_slh_first = (elm)->field.sle_next = (head)->slh_first;       \
    } while (atomic_cmpxchg(&(head)->slh_first, old_slh_first, (elm)) != \
             old_slh_first);                                             \
    old_slh_first;      })

#define SLIST_MOVE_ATOMIC(dest, src) do {                            \
    (dest)->slh_first = atomic_xchg(&(src)->slh_first, NULL);        \
} while (/*CONSTCOND*/0)

#define SLIST_FIRST_RCU(head)       atomic_rcu_read(&(head)->slh_first)
