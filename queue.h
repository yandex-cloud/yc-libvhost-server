/*
 * Lists and queues.
 *
 * Relevant OSes provide BSD-originated sys/queue.h, so just use it here, with
 * a few extensions.
 */

#pragma once

#include <sys/queue.h>
#include "atomic.h"

/*
 * Cater to the strict _Atomic-qual checking of clang and define a version of
 * SLIST_HEAD usable with the below atomic ops.  Aside from the _Atomic
 * qualifier it's identical to the original SLIST_HEAD, so all other SLIST_*
 * ops work fine on it.
 */
#define SLIST_HEAD_ATOMIC(name, type)                           \
    struct name {                                               \
        struct type * _Atomic slh_first; /* first element */    \
    }

/*
 * Atomically insert a new list head
 */
#define SLIST_INSERT_HEAD_ATOMIC(head, elm, field)      ({                        \
    typeof(elm) old_slh_first;                                                    \
    do {                                                                          \
        /* Grab the current head and make the new element point to it */          \
        (elm)->field.sle_next = (head)->slh_first;                                \
        old_slh_first = (elm)->field.sle_next;                                    \
                                                                                  \
        /* Repeat until slh_first matches old_slh_first at the time of cmpxchg */ \
    } while (atomic_cmpxchg(&(head)->slh_first, old_slh_first, (elm)) !=          \
             old_slh_first);                                                      \
    old_slh_first;      })

/*
 * Atomically move the list into 'dest' leaving 'src' empty
 */
#define SLIST_MOVE_ATOMIC(dest, src) do {                            \
    (dest)->slh_first = atomic_xchg(&(src)->slh_first, NULL);        \
} while (0)

/*
 * Read the current list head with consume
 */
#define SLIST_FIRST_RCU(head)       atomic_rcu_read(&(head)->slh_first)
