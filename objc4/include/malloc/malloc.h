
#ifndef _SUBJ_MALLOC_MALLOC_H_
#define _SUBJ_MALLOC_MALLOC_H_

#if defined(SUBJECTIVE_WIN32) && SUBJECTIVE_WIN32

// static __inline void bcopy(const void *src, void *dst, size_t size) { memcpy(dst, src, size); }
// static __inline void bzero(void *dst, size_t size) { memset(dst, 0, size); }

// int asprintf(char **dstp, const char *format, ...);

typedef void * malloc_zone_t;

static __inline malloc_zone_t* malloc_default_zone(void) { return (malloc_zone_t*)-1; }
static __inline void *malloc_zone_malloc(malloc_zone_t z, size_t size) { return malloc(size); }
static __inline void *malloc_zone_calloc(malloc_zone_t z, size_t size, size_t count) { return calloc(size, count); }
static __inline void *malloc_zone_realloc(malloc_zone_t z, void *p, size_t size) { return realloc(p, size); }
static __inline void malloc_zone_free(malloc_zone_t z, void *p) { free(p); }
static __inline malloc_zone_t malloc_zone_from_ptr(const void *p) { return (malloc_zone_t)-1; }
static __inline size_t malloc_size(const void *p) { return _msize((void*)p); /* fixme invalid pointer check? */ }

#else

#include_next <malloc/malloc.h>

#endif

#endif
