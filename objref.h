/*
 * Generic reference counting infrastructure.  Modelled after Linux kref.h,
 * with a notable exception that the release function is stored on the
 * refcounting object at init rather than passed into the put method.
 *
 * Note: refcounts need more relaxed memory ordering that regular atomics.
 *
 * The increments provide no ordering, because it's expected that the object is
 * held by something else that provides ordering.
 *
 * The decrements provide release order, such that all the prior loads and
 * stores will be issued before, it also provides a control dependency, which
 * will order against the subsequent free().
 *
 * The control dependency is against the load of the cmpxchg (ll/sc) that
 * succeeded. This means the stores aren't fully ordered, but this is fine
 * because the 1->0 transition indicates no concurrency.
 *
 * The decrements dec_and_test() and sub_and_test() also provide acquire
 * ordering on success.
 */

#pragma once

#include <stdbool.h>
#include "catomic.h"

struct objref {
    atomic_ulong refcount;
    void (*release)(struct objref *objref);
};

static inline void objref_init(struct objref *objref,
                               void (*release)(struct objref *objref))
{
    objref->release = release;
    atomic_set(&objref->refcount, 1);
}

static inline unsigned int objref_read(struct objref *objref)
{
    return atomic_read(&objref->refcount);
}

static inline void refcount_inc(atomic_ulong *ptr)
{
    atomic_fetch_add_explicit(ptr, 1, memory_order_relaxed);
}

static inline void objref_get(struct objref *objref)
{
    refcount_inc(&objref->refcount);
}

static inline bool refcount_dec_and_test(atomic_ulong *ptr)
{
    atomic_ulong old = atomic_fetch_sub_explicit(ptr, 1, memory_order_release);

    if (old == 1) {
        smp_mb_acquire();
        return true;
    }
    return false;
}

/*
 * Decrement refcount for object, and call @release if it drops to zero.
 * Return true if the object was removed, otherwise return false.
 * Note: only "true" is trustworthy, "false" doesn't prevent another thread
 * from releasing the object.
 */
static inline bool objref_put(struct objref *objref)
{
    if (refcount_dec_and_test(&objref->refcount)) {
        objref->release(objref);
        return true;
    }
    return false;
}
