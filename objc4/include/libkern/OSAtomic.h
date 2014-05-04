
#ifndef SUBJ_LIBKERN_OSATOMIC__H
#define SUBJ_LIBKERN_OSATOMIC__H

#if defined(SUBJECTIVE_WIN32) && SUBJECTIVE_WIN32

#ifdef __cplusplus
extern "C" {
#endif

#include <Windows.h>


static inline bool OSAtomicCompareAndSwapLong(long oldl, long newl, long volatile *dst)
{ 
	// fixme barrier is overkill
	long original = InterlockedCompareExchange(dst, newl, oldl);
	return (original == oldl);
}

static inline bool OSAtomicCompareAndSwapPtrBarrier(void *oldp, void *newp, void * volatile *dst)
{ 
	void *original = InterlockedCompareExchangePointer(dst, newp, oldp);
	return (original == oldp);
}

static inline bool OSAtomicCompareAndSwap32Barrier(int32_t oldl, int32_t newl, int32_t volatile *dst)
{ 
	long original = InterlockedCompareExchange((volatile long *)dst, newl, oldl);
	return (original == oldl);
}

static inline int32_t OSAtomicDecrement32Barrier(volatile int32_t *dst)
{
	return InterlockedDecrement((volatile long *)dst);
}

static inline int32_t OSAtomicIncrement32Barrier(volatile int32_t *dst)
{
	return InterlockedIncrement((volatile long *)dst);
}


typedef LONG OSSpinLock;

#define OS_SPINLOCK_INIT 0

static inline  bool OSSpinLockTry(OSSpinLock *slock)
{
    return InterlockedExchange(slock, 1) == 0;
}

static inline void OSSpinLockLock(OSSpinLock *slock)
{
    while (InterlockedExchange(slock, 1) != 0)
        Sleep(1);   // 1ms
}

static inline void OSSpinLockUnlock(OSSpinLock *lock) {
    *lock = 0;
}


#ifdef __cplusplus
}
#endif

#else

#include_next <libkern/OSAtomic.h>

#endif

#endif
