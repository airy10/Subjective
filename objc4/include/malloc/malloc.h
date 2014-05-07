
#ifndef _SUBJ_MALLOC_MALLOC_H_
#define _SUBJ_MALLOC_MALLOC_H_

#if TARGET_OS_WIN32

#include <malloc.h>

typedef void * malloc_zone_t;

static inline malloc_zone_t* malloc_default_zone(void)
	{ return (malloc_zone_t*)-1; }

static inline void *malloc_zone_malloc(malloc_zone_t z, size_t size)
	{ return malloc(size); }

static inline void *malloc_zone_calloc(malloc_zone_t z, size_t size, size_t count)
	{ return calloc(size, count); }

static inline void *malloc_zone_realloc(malloc_zone_t z, void *p, size_t size)
	{ return realloc(p, size); }

static inline void malloc_zone_free(malloc_zone_t z, void *p)
	{ free(p); }

static inline malloc_zone_t malloc_zone_from_ptr(const void *p)
	{ return (malloc_zone_t)-1; }

static inline size_t malloc_size(const void *p)
	{ return _msize((void*)p); /* fixme invalid pointer check? */ }

static inline void* malloc_zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size)
	{ return _aligned_malloc(size, size); }


#else

#include_next <malloc/malloc.h>

#endif

#endif
