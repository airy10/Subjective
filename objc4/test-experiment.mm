
#if defined(SUBJECTIVE_WIN32) && SUBJECTIVE_WIN32

#include <stdio.h>

#import "objc-runtime.h"

#else

#import "Foundation/NSObject.h"

#include <algorithm>

#import "objc-private.h"
#import "objc-runtime.h"
#import "objc-runtime-new.h"
#import "objc-exception.h"
#import "objc-file.h"

#define X8(x) \
    x x x x x x x x
#define X64(x) \
    X8(x) X8(x) X8(x) X8(x) X8(x) X8(x) X8(x) X8(x)
#define X128(x) \
    X64(x) X64(x)

// hack to avoid conflicts with compiler's internal declaration
asm("\n .data"
    "\n .globl __objc_empty_vtable "
    "\n __objc_empty_vtable:"
#if __LP64__
    X128("\n .quad _objc_msgSend")
#else
    X128("\n .long _objc_msgSend")
#endif
    );

const char *_gcForHInfo(const header_info *hinfo)
{
    return "";
}
const char *_gcForHInfo2(const header_info *hinfo)
{
    return "";
}

bool crashlog_header_name(header_info *hi)
{
    return crashlog_header_name_string(hi ? hi->fname : NULL);
}

bool crashlog_header_name_string(const char *name)
{
    CRSetCrashLogMessage2(name);
    return true;
}

struct class_t * getPreoptimizedClass(const char *name)
{
    return NULL;
}


void 
inform_duplicate(const char *name, Class oldCls, Class cls)
{
    _objc_inform ("Class %s is implemented in two different images.", name);
}

bool isPreoptimized(void) 
{
    return false;
}


const char *__crashreporter_info__ = NULL;

const char *CRSetCrashLogMessage(const char *msg)
{
    __crashreporter_info__ = msg;
    return msg;
}
const char *CRGetCrashLogMessage(void)
{
    return __crashreporter_info__;
}

const char *CRSetCrashLogMessage2(const char *msg)
{
    // sorry
    return msg;
}

typedef struct {
    SEL name;     // same layout as struct old_method
    void *unused;
    IMP imp;  // same layout as struct old_method
} cache_entry;


void __objc_error(id rcv, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    printf(fmt, args);
    va_end(args);
    abort();
}


void _objc_fatal(const char *fmt, ...)
{
    va_list ap; 
    char *buf1;
    char *buf2;

    va_start(ap,fmt); 
    vasprintf(&buf1, fmt, ap);
    va_end (ap);

    asprintf(&buf2, "objc[%d]: %s\n", getpid(), buf1);

    abort();
}


void _objc_inform(const char *fmt, ...)
{
    va_list ap; 
    char *buf1;
    char *buf2;

    va_start (ap,fmt); 
    vasprintf(&buf1, fmt, ap);
    va_end (ap);

    asprintf(&buf2, "objc[%d]: %s\n", getpid(), buf1);

    free(buf2);
    free(buf1);
}


void *_malloc_internal(size_t size) 
{
    return malloc_zone_malloc(_objc_internal_zone(), size);
}


void *_calloc_internal(size_t count, size_t size)
{
    return malloc_zone_calloc(_objc_internal_zone(), count, size);
}


void *_realloc_internal(void *ptr, size_t size)
{
    return malloc_zone_realloc(_objc_internal_zone(), ptr, size);
}


size_t _malloc_size_internal(void *ptr)
{
    malloc_zone_t *zone = _objc_internal_zone();
    return zone->size(zone, ptr);
}


void _free_internal(void *ptr)
{
    malloc_zone_free(_objc_internal_zone(), ptr);
}


char *_strdup_internal(const char *str)
{
    size_t len;
    char *dup;
    if (!str) return NULL;
    len = strlen(str);
    dup = (char *)malloc_zone_malloc(_objc_internal_zone(), len + 1);
    memcpy(dup, str, len + 1);
    return dup;
}


void *_memdup_internal(const void *mem, size_t len)
{
    void *dup = malloc_zone_malloc(_objc_internal_zone(), len);
    memcpy(dup, mem, len);
    return dup;
}


malloc_zone_t *_objc_internal_zone(void)
{
    static malloc_zone_t *z = (malloc_zone_t *)-1;
    if (z == (malloc_zone_t *)-1) {
        if (UseInternalZone) {
            z = malloc_create_zone(vm_page_size, 0);
            malloc_set_zone_name(z, "ObjC");
        } else {
            z = malloc_default_zone();
        }
    }
    return z;
}


@interface NSInvocation
- (SEL)selector;
@end

// better to not rely on Foundation to build
@class NSString;
@class NSMethodSignature;
#ifdef __LP64__
typedef unsigned long NSUInteger;
#else
typedef unsigned int NSUInteger;
#endif
typedef struct _NSZone NSZone;

#define newcls(cls) ((class_t *)cls)
#define newmethod(meth) ((method_t *)meth)
#define newivar(ivar) ((ivar_t *)ivar)
#define newcategory(cat) ((category_t *)cat)
#define newprotocol(p) ((protocol_t *)p)
#define newproperty(p) ((property_t *)p)


SEL SEL_load = NULL;
SEL SEL_initialize = NULL;
SEL SEL_resolveInstanceMethod = NULL;
SEL SEL_resolveClassMethod = NULL;
SEL SEL_cxx_construct = NULL;
SEL SEL_cxx_destruct = NULL;
SEL SEL_retain = NULL;
SEL SEL_release = NULL;
SEL SEL_autorelease = NULL;
SEL SEL_retainCount = NULL;
SEL SEL_alloc = NULL;
SEL SEL_allocWithZone = NULL;
SEL SEL_copy = NULL;
SEL SEL_new = NULL;
SEL SEL_finalize = NULL;
SEL SEL_forwardInvocation = NULL;

static uint32_t fixed_up_method_list = 3;

void
disableSharedCacheOptimizations(void)
{
    fixed_up_method_list = 1;
}


void preopt_init(void)
{
    disableSharedCacheOptimizations();
    
    if (PrintPreopt) {
        _objc_inform("PREOPTIMIZATION: is DISABLED "
                     "(not supported on ths platform)");
    }
}

header_info *preoptimizedHinfoForHeader(const headerType *mhdr)
{
    return NULL;
}



rwlock_t runtimeLock;
rwlock_t selLock;
mutex_t cacheUpdateLock = MUTEX_INITIALIZER;
recursive_mutex_t loadMethodLock = RECURSIVE_MUTEX_INITIALIZER;

static tls_key_t _objc_pthread_key;


void recursive_mutex_init(recursive_mutex_t *m)
{
    // fixme error checking
    pthread_mutex_t *newmutex;

    // Build recursive mutex attributes, if needed
    static pthread_mutexattr_t *attr;
    if (!attr) {
        pthread_mutexattr_t *newattr = (pthread_mutexattr_t *)
            _malloc_internal(sizeof(pthread_mutexattr_t));
        pthread_mutexattr_init(newattr);
        pthread_mutexattr_settype(newattr, PTHREAD_MUTEX_RECURSIVE);
        while (!attr) {
            if (OSAtomicCompareAndSwapPtrBarrier(0, newattr, (void**)&attr)) {
                // we win
                goto attr_done;
            }
        }
        // someone else built the attr first
        _free_internal(newattr);
    }
 attr_done:

    // Build the mutex itself
    newmutex = (pthread_mutex_t *)_malloc_internal(sizeof(pthread_mutex_t));
    pthread_mutex_init(newmutex, attr);
    while (!m->mutex) {
        if (OSAtomicCompareAndSwapPtrBarrier(0, newmutex, (void**)&m->mutex)) {
            // we win
            return;
        }
    }
    
    // someone else installed their mutex first
    pthread_mutex_destroy(newmutex);
}


void lock_init(void)
{
    rwlock_init(&selLock);
    rwlock_init(&runtimeLock);
    recursive_mutex_init(&loadMethodLock);
}


void lockForMethodLookup(void)
{
    rwlock_read(&runtimeLock);
}


void unlockForMethodLookup(void)
{
    rwlock_unlock_read(&runtimeLock);
}


void _destroySyncCache(struct SyncCache *cache)
{
    if (cache) free(cache);
}


typedef struct _objc_initializing_classes {
    int classesAllocated;
    Class *metaclasses;
} _objc_initializing_classes;


_objc_pthread_data *_objc_fetch_pthread_data(BOOL create)
{
    _objc_pthread_data *data;

    data = (_objc_pthread_data *)tls_get(_objc_pthread_key);
    if (!data  &&  create) {
        data = (_objc_pthread_data *)
            _calloc_internal(1, sizeof(_objc_pthread_data));
        tls_set(_objc_pthread_key, data);
    }

    return data;
}


void _objc_pthread_destroyspecific(void *arg)
{
    _objc_pthread_data *data = (_objc_pthread_data *)arg;
    if (data != NULL) {
        _destroyInitializingClassList(data->initializingClasses);
        _destroySyncCache(data->syncCache);
        _destroyAltHandlerList(data->handlerList);

        // add further cleanup here...

        _free_internal(data);
    }
}


void tls_init(void)
{
    _objc_pthread_key = tls_create(&_objc_pthread_destroyspecific);
}


id objc_noop_imp(id self, SEL _cmd) {
    return self;
}


Cache
_class_getCache(Class cls)
{
    return newcls(cls)->cache;
}


static BOOL isRealized(class_t *cls)
{
    return (cls->data()->flags & RW_REALIZED) ? YES : NO;
}


static BOOL isFuture(class_t *cls)
{
    return (cls->data()->flags & RW_FUTURE) ? YES : NO;
}


struct objc_method_description *
method_getDescription(Method m)
{
    if (!m) return NULL;
    return (struct objc_method_description *)newmethod(m);
}


static NXMapTable *remappedClasses(BOOL create)
{
    static NXMapTable *remapped_class_map = NULL;

    rwlock_assert_locked(&runtimeLock);

    if (remapped_class_map) return remapped_class_map;
    if (!create) return NULL;

    // remapped_class_map is big enough to hold CF's classes and a few others
    INIT_ONCE_PTR(remapped_class_map, 
                  NXCreateMapTableFromZone(NXPtrValueMapPrototype, 32, 
                                           _objc_internal_zone()), 
                  NXFreeMapTable(v));

    return remapped_class_map;
}


static class_t *remapClass(class_t *cls)
{
    rwlock_assert_locked(&runtimeLock);

    class_t *c2;

    if (!cls) return NULL;

    if (NXMapMember(remappedClasses(YES), cls, (void**)&c2) == NX_MAPNOTAKEY) {
        return cls;
    } else {
        return c2;
    }
}


static class_t *remapClass(classref_t cls)
{
    return remapClass((class_t *)cls);
}


Class
_category_getClass(Category cat)
{
    rwlock_read(&runtimeLock);
    class_t *result = remapClass(newcategory(cat)->cls);
    assert(isRealized(result));  // ok for call_category_loads' usage
    rwlock_unlock_read(&runtimeLock);
    return (Class)result;
}


static class_t *
getSuperclass(class_t *cls)
{
    if (!cls) return NULL;
    return cls->superclass;
}


void 
_class_setCache(Class cls, Cache cache)
{
    newcls(cls)->cache = cache;
}


void 
_class_setGrowCache(Class cls, BOOL grow)
{
    // fixme good or bad for memory use?
}


BOOL 
_class_shouldGrowCache(Class cls)
{
    return YES; // fixme good or bad for memory use?
}


static Method look_up_method(Class cls, SEL sel,
                             BOOL withCache, BOOL withResolver)
{
    Method meth = NULL;

    if (withCache) {
        meth = _cache_getMethod(cls, sel, _objc_msgForward_internal);
        if (meth == (Method)1) {
            // Cache contains forward:: . Stop searching.
            return NULL;
        }
    }

    if (!meth) meth = _class_getMethod(cls, sel);

    if (!meth  &&  withResolver) meth = _class_resolveMethod(cls, sel);

    return meth;
}


#define FOREACH_METHOD_LIST(_mlist, _cls, code)                         \
    do {                                                                \
        const method_list_t *_mlist;                                    \
        if (_cls->data()->method_lists) {                               \
            if (_cls->data()->flags & RW_METHOD_ARRAY) {                \
                method_list_t **_mlistp;                                \
                for (_mlistp=_cls->data()->method_lists; *_mlistp; _mlistp++){\
                    _mlist = *_mlistp;                                  \
                    code                                                \
                }                                                       \
            } else {                                                    \
                _mlist = _cls->data()->method_list;                     \
                code                                                    \
            }                                                           \
        }                                                               \
    } while (0) 


#define FOREACH_REALIZED_CLASS_AND_SUBCLASS(_c, _cls, code)             \
    do {                                                                \
        rwlock_assert_writing(&runtimeLock);                            \
        class_t *_top = _cls;                                           \
        class_t *_c = _top;                                             \
        if (_c) {                                                       \
            while (1) {                                                 \
                code                                                    \
                if (_c->data()->firstSubclass) {                          \
                    _c = _c->data()->firstSubclass;                       \
                } else {                                                \
                    while (!_c->data()->nextSiblingClass  &&  _c != _top) { \
                        _c = getSuperclass(_c);                         \
                    }                                                   \
                    if (_c == _top) break;                              \
                    _c = _c->data()->nextSiblingClass;                    \
                }                                                       \
            }                                                           \
        } else {                                                        \
            /* nil means all realized classes */                        \
            NXHashTable *_classes = realizedClasses();                  \
            NXHashTable *_metaclasses = realizedMetaclasses();          \
            NXHashState _state;                                         \
            _state = NXInitHashState(_classes);                         \
            while (NXNextHashState(_classes, &_state, (void**)&_c))    \
            {                                                           \
                code                                                    \
            }                                                           \
            _state = NXInitHashState(_metaclasses);                     \
            while (NXNextHashState(_metaclasses, &_state, (void**)&_c)) \
            {                                                           \
                code                                                    \
            }                                                           \
        }                                                               \
    } while (0)





static Method _class_resolveClassMethod(Class cls, SEL sel)
{
    BOOL resolved;
    Method meth = NULL;
    Class clsInstance;

    if (!look_up_method(cls, SEL_resolveClassMethod, 
                        YES /*cache*/, NO /*resolver*/))
    {
        return NULL;
    }

    // GrP fixme same hack as +initialize
    if (strncmp(_class_getName(cls), "_%", 2) == 0) {
        // Posee's meta's name is smashed and isn't in the class_hash, 
        // so objc_getClass doesn't work.
        const char *baseName = strchr(_class_getName(cls), '%'); // get posee's real name
        clsInstance = (Class)objc_getClass(baseName);
    } else {
        clsInstance = (Class)objc_getClass(_class_getName(cls));
    }
    
    resolved = ((BOOL(*)(id, SEL, SEL))objc_msgSend)((id)clsInstance, SEL_resolveClassMethod, sel);

    if (resolved) {
        // +resolveClassMethod adds to self->isa
        meth = look_up_method(cls, sel, YES/*cache*/, NO/*resolver*/);

        if (!meth) {
            // Method resolver didn't add anything?
            _objc_inform("+[%s resolveClassMethod:%s] returned YES, but "
                         "no new implementation of +[%s %s] was found", 
                         class_getName(cls),
                         sel_getName(sel), 
                         class_getName(cls), 
                         sel_getName(sel));
            return NULL;
        }
    }

    return meth;
}


static Method _class_resolveInstanceMethod(Class cls, SEL sel)
{
    BOOL resolved;
    Method meth = NULL;

    if (!look_up_method(((id)cls)->isa, SEL_resolveInstanceMethod, 
                        YES /*cache*/, NO /*resolver*/))
    {
        return NULL;
    }

    resolved = ((BOOL(*)(id, SEL, SEL))objc_msgSend)((id)cls, SEL_resolveInstanceMethod, sel);

    if (resolved) {
        // +resolveClassMethod adds to self
        meth = look_up_method(cls, sel, YES/*cache*/, NO/*resolver*/);

        if (!meth) {
            // Method resolver didn't add anything?
            _objc_inform("+[%s resolveInstanceMethod:%s] returned YES, but "
                         "no new implementation of %c[%s %s] was found", 
                         class_getName(cls),
                         sel_getName(sel), 
                         class_isMetaClass(cls) ? '+' : '-', 
                         class_getName(cls), 
                         sel_getName(sel));
            return NULL;
        }
    }

    return meth;
}


static BOOL isMethodListFixedUp(const method_list_t *mlist)
{
    return (mlist->entsize_NEVER_USE & 3) == fixed_up_method_list;
}


static method_t *findMethodInSortedMethodList(SEL key, const method_list_t *list)
{
    const method_t * const first = &list->first;
    const method_t *base = first;
    const method_t *probe;
    uintptr_t keyValue = (uintptr_t)key;
    uint32_t count;
    
    for (count = list->count; count != 0; count >>= 1) {
        probe = base + (count >> 1);
        
        uintptr_t probeValue = (uintptr_t)probe->name;
        
        if (keyValue == probeValue) {
            // `probe` is a match.
            // Rewind looking for the *first* occurrence of this value.
            // This is required for correct category overrides.
            while (probe > first && keyValue == (uintptr_t)probe[-1].name) {
                probe--;
            }
            return (method_t *)probe;
        }
        
        if (keyValue > probeValue) {
            base = probe + 1;
            count--;
        }
    }
    
    return NULL;
}


static method_t *search_method_list(const method_list_t *mlist, SEL sel)
{
    int methodListIsFixedUp = isMethodListFixedUp(mlist);
    int methodListHasExpectedSize = mlist->getEntsize() == sizeof(method_t);
    
    if (__builtin_expect(methodListIsFixedUp && methodListHasExpectedSize, 1)) {
        return findMethodInSortedMethodList(sel, mlist);
    } else {
        // Linear search of unsorted method list
        method_list_t::method_iterator iter = mlist->begin();
        method_list_t::method_iterator end = mlist->end();
        for ( ; iter != end; ++iter) {
            if (iter->name == sel) return &*iter;
        }
    }

#ifndef NDEBUG
    // sanity-check negative results
    if (isMethodListFixedUp(mlist)) {
        method_list_t::method_iterator iter = mlist->begin();
        method_list_t::method_iterator end = mlist->end();
        for ( ; iter != end; ++iter) {
            if (iter->name == sel) {
                _objc_fatal("linear search worked when binary search did not");
            }
        }
    }
#endif

    return NULL;
}


static method_t *
getMethodNoSuper_nolock(class_t *cls, SEL sel)
{
    rwlock_assert_locked(&runtimeLock);

    assert(isRealized(cls));
    // fixme nil cls? 
    // fixme NULL sel?

    FOREACH_METHOD_LIST(mlist, cls, {
        method_t *m = search_method_list(mlist, sel);
        if (m) return m;
    });

    return NULL;
}


static method_t *
getMethod_nolock(class_t *cls, SEL sel)
{
    method_t *m = NULL;

    rwlock_assert_locked(&runtimeLock);

    // fixme nil cls?
    // fixme NULL sel?

    assert(isRealized(cls));

    while (cls  &&  ((m = getMethodNoSuper_nolock(cls, sel))) == NULL) {
        cls = getSuperclass(cls);
    }

    return m;
}


Method _class_getMethod(Class cls, SEL sel)
{
    Method m;
    rwlock_read(&runtimeLock);
    m = (Method)getMethod_nolock(newcls(cls), sel);
    rwlock_unlock_read(&runtimeLock);
    return m;
}


Method _class_resolveMethod(Class cls, SEL sel)
{
    Method meth = NULL;

    if (_class_isMetaClass(cls)) {
        meth = _class_resolveClassMethod(cls, sel);
    }
    if (!meth) {
        meth = _class_resolveInstanceMethod(cls, sel);
    }

    if (PrintResolving  &&  meth) {
        _objc_inform("RESOLVE: method %c[%s %s] dynamically resolved to %p", 
                     class_isMetaClass(cls) ? '+' : '-', 
                     class_getName(cls), sel_getName(sel), 
                     method_getImplementation(meth));
    }
    
    return meth;
}


static uint32_t method_list_count(const method_list_t *mlist)
{
    return mlist ? mlist->count : 0;
}


static method_list_t *
fixupMethodList(method_list_t *mlist, bool bundleCopy, bool sort);


static uint32_t method_list_entsize(const method_list_t *mlist)
{
    return mlist->entsize_NEVER_USE & ~(uint32_t)3;
}


static method_t *method_list_nth(const method_list_t *mlist, uint32_t i)
{
    assert(i < mlist->count);
    return (method_t *)(i*method_list_entsize(mlist) + (char *)&mlist->first);
}


static void method_list_swap(method_list_t *mlist, uint32_t i, uint32_t j)
{
    size_t entsize = method_list_entsize(mlist);
    char temp[entsize];
    memcpy(temp, method_list_nth(mlist, i), entsize);
    memcpy(method_list_nth(mlist, i), method_list_nth(mlist, j), entsize);
    memcpy(method_list_nth(mlist, j), temp, entsize);
}


static uint32_t method_list_index(const method_list_t *mlist,const method_t *m)
{
    uint32_t i = (uint32_t)(((uintptr_t)m - (uintptr_t)mlist) / method_list_entsize(mlist));
    assert(i < mlist->count);
    return i;
}


static void getExtendedTypesIndexesForMethod(protocol_t *proto, const method_t *m, BOOL isRequiredMethod, BOOL isInstanceMethod, uint32_t& a, uint32_t &b)
{
    a = 0;

    if (isRequiredMethod && isInstanceMethod) {
        b = method_list_index(proto->instanceMethods, m);
        return;
    }
    a += method_list_count(proto->instanceMethods);

    if (isRequiredMethod && !isInstanceMethod) {
        b = method_list_index(proto->classMethods, m);
        return;
    }
    a += method_list_count(proto->classMethods);

    if (!isRequiredMethod && isInstanceMethod) {
        b = method_list_index(proto->optionalInstanceMethods, m);
        return;
    }
    a += method_list_count(proto->optionalInstanceMethods);

    if (!isRequiredMethod && !isInstanceMethod) {
        b = method_list_index(proto->optionalClassMethods, m);
        return;
    }
    a += method_list_count(proto->optionalClassMethods);
}


static NXMapTable *protocols(void)
{
    static NXMapTable *protocol_map = NULL;
    
    rwlock_assert_locked(&runtimeLock);

    INIT_ONCE_PTR(protocol_map, 
                  NXCreateMapTableFromZone(NXStrValueMapPrototype, 16, 
                                           _objc_internal_zone()), 
                  NXFreeMapTable(v) );

    return protocol_map;
}


static protocol_t *remapProtocol(protocol_ref_t proto)
{
    rwlock_assert_locked(&runtimeLock);

    protocol_t *newproto = (protocol_t *)
        NXMapGet(protocols(), ((protocol_t *)proto)->name);
    return newproto ? newproto : (protocol_t *)proto;
}


static BOOL _protocol_conformsToProtocol_nolock(protocol_t *self, protocol_t *other)
{
    if (!self  ||  !other) {
        return NO;
    }

    if (0 == strcmp(self->name, other->name)) {
        return YES;
    }

    if (self->protocols) {
        uintptr_t i;
        for (i = 0; i < self->protocols->count; i++) {
            protocol_t *proto = remapProtocol(self->protocols->list[i]);
            if (0 == strcmp(other->name, proto->name)) {
                return YES;
            }
            if (_protocol_conformsToProtocol_nolock(proto, other)) {
                return YES;
            }
        }
    }

    return NO;
}


const char *
protocol_getName(Protocol *proto)
{
    return newprotocol(proto)->name;
}


BOOL protocol_isEqual(Protocol *self, Protocol *other)
{
    if (self == other) return YES;
    if (!self  ||  !other) return NO;

    if (!protocol_conformsToProtocol(self, other)) return NO;
    if (!protocol_conformsToProtocol(other, self)) return NO;

    return YES;
}


BOOL protocol_conformsToProtocol(Protocol *self, Protocol *other)
{
    BOOL result;
    rwlock_read(&runtimeLock);
    result = _protocol_conformsToProtocol_nolock(newprotocol(self), 
                                                 newprotocol(other));
    rwlock_unlock_read(&runtimeLock);
    return result;
}


IMP class_getMethodImplementation(Class cls, SEL sel)
{
    IMP imp;

    if (!cls  ||  !sel) return NULL;

    imp = lookUpMethod(cls, sel, YES/*initialize*/, YES/*cache*/, nil);

    // Translate forwarding function to C-callable external version
    if (imp == _objc_msgForward_internal) {
        return _objc_msgForward;
    }

    return imp;
}


BOOL class_conformsToProtocol(Class cls_gen, Protocol *proto_gen)
{
    class_t *cls = newcls(cls_gen);
    protocol_t *proto = newprotocol(proto_gen);
    const protocol_list_t **plist;
    unsigned int i;
    BOOL result = NO;
    
    if (!cls_gen) return NO;
    if (!proto_gen) return NO;

    rwlock_read(&runtimeLock);

    assert(isRealized(cls));

    for (plist = cls->data()->protocols; plist  &&  *plist; plist++) {
        for (i = 0; i < (*plist)->count; i++) {
            protocol_t *p = remapProtocol((*plist)->list[i]);
            if (p == proto || _protocol_conformsToProtocol_nolock(p, proto)) {
                result = YES;
                goto done;
            }
        }
    }

 done:
    rwlock_unlock_read(&runtimeLock);

    return result;
}


static method_t *
_protocol_getMethod_nolock(protocol_t *proto, SEL sel, 
                           BOOL isRequiredMethod, BOOL isInstanceMethod, 
                           BOOL recursive)
{
    rwlock_assert_writing(&runtimeLock);

    if (!proto  ||  !sel) return NULL;

    method_list_t **mlistp = NULL;

    if (isRequiredMethod) {
        if (isInstanceMethod) {
            mlistp = &proto->instanceMethods;
        } else {
            mlistp = &proto->classMethods;
        }
    } else {
        if (isInstanceMethod) {
            mlistp = &proto->optionalInstanceMethods;
        } else {
            mlistp = &proto->optionalClassMethods;
        }
    }

    if (*mlistp) {
        method_list_t *mlist = *mlistp;
        if (!isMethodListFixedUp(mlist)) {
            bool hasExtendedMethodTypes = proto->hasExtendedMethodTypes();
            mlist = fixupMethodList(mlist, true/*always copy for simplicity*/,
                                    !hasExtendedMethodTypes/*sort if no ext*/);
            *mlistp = mlist;

            if (hasExtendedMethodTypes) {
                // Sort method list and extended method types together.
                // fixupMethodList() can't do this.
                // fixme COW stomp
                uint32_t count = method_list_count(mlist);
                uint32_t prefix;
                uint32_t unused;
                getExtendedTypesIndexesForMethod(proto, method_list_nth(mlist, 0), isRequiredMethod, isInstanceMethod, prefix, unused);
                const char **types = proto->extendedMethodTypes;
                for (uint32_t i = 0; i < count; i++) {
                    for (uint32_t j = i+1; j < count; j++) {
                        method_t *mi = method_list_nth(mlist, i);
                        method_t *mj = method_list_nth(mlist, j);
                        if (mi->name > mj->name) {
                            method_list_swap(mlist, i, j);
                            std::swap(types[prefix+i], types[prefix+j]);
                        }
                    }
                }
            }
        }

        method_t *m = search_method_list(mlist, sel);
        if (m) return m;
    }

    if (recursive  &&  proto->protocols) {
        method_t *m;
        for (uint32_t i = 0; i < proto->protocols->count; i++) {
            protocol_t *realProto = remapProtocol(proto->protocols->list[i]);
            m = _protocol_getMethod_nolock(realProto, sel, 
                                           isRequiredMethod, isInstanceMethod, 
                                           true);
            if (m) return m;
        }
    }

    return NULL;
}


Method
_protocol_getMethod(Protocol *p, SEL sel, BOOL isRequiredMethod, BOOL isInstanceMethod, BOOL recursive)
{
    rwlock_write(&runtimeLock);
    method_t *result = _protocol_getMethod_nolock(newprotocol(p), sel, 
                                                  isRequiredMethod,
                                                  isInstanceMethod, 
                                                  recursive);
    rwlock_unlock_write(&runtimeLock);
    return (Method)result;
}


static BOOL
isMetaClass(class_t *cls)
{
    assert(cls);
    assert(isRealized(cls));
    return (cls->data()->ro->flags & RO_META) ? YES : NO;
}

BOOL _class_isMetaClass(Class cls)
{
    if (!cls) return NO;
    return isMetaClass(newcls(cls));
}

BOOL class_isMetaClass(Class cls)
{
    return _class_isMetaClass(cls);
}

class_t *getMeta(class_t *cls)
{
    if (isMetaClass(cls)) return cls;
    else return cls->isa;
}

Class _class_getMeta(Class cls)
{
    return (Class)getMeta(newcls(cls));
}

Class
_class_getSuperclass(Class cls)
{
    return (Class)getSuperclass(newcls(cls));
}


Class class_getSuperclass(Class cls)
{
    return _class_getSuperclass(cls);
}


BOOL class_respondsToSelector(Class cls, SEL sel)
{
    IMP imp;

    if (!sel  ||  !cls) return NO;

    // Avoids +initialize because it historically did so.
    // We're not returning a callable IMP anyway.
    imp = lookUpMethod(cls, sel, NO/*initialize*/, YES/*cache*/, nil);
    return (imp != (IMP)_objc_msgForward_internal) ? YES : NO;
}


BOOL 
_class_isInitializing(Class cls_gen)
{
    class_t *cls = newcls(_class_getMeta(cls_gen));
    return (cls->data()->flags & RW_INITIALIZING) ? YES : NO;
}


BOOL
_class_isInitialized(Class cls_gen)
{
    class_t *cls = newcls(_class_getMeta(cls_gen));
    return (cls->data()->flags & RW_INITIALIZED) ? YES : NO;
}


static void changeInfo(class_t *cls, unsigned int set, unsigned int clear);

void
_class_setInitialized(Class cls_gen)
{
    class_t *metacls;
    class_t *cls;

    rwlock_write(&runtimeLock);

    assert(!_class_isMetaClass(cls_gen));

    cls = newcls(cls_gen);
    metacls = getMeta(cls);

#if SUPPORT_VTABLE
    // Update vtables (initially postponed pending +initialize completion)
    // Do cls first because root metacls is a subclass of root cls
    updateVtable(cls, YES);
    updateVtable(metacls, YES);
#endif

    rwlock_unlock_write(&runtimeLock);

    changeInfo(metacls, RW_INITIALIZED, RW_INITIALIZING);
}


void 
_class_setInitializing(Class cls_gen)
{
    assert(!_class_isMetaClass(cls_gen));
    class_t *cls = newcls(_class_getMeta(cls_gen));
    changeInfo(cls, RW_INITIALIZING, 0);
}


static const char *
getName(class_t *cls)
{
    // fixme hack rwlock_assert_writing(&runtimeLock);
    assert(cls);

    if (isRealized(cls)) {
        return cls->data()->ro->name;
    } else {
        return ((const class_ro_t *)cls->data())->name;
    }
}


const char *_class_getName(Class cls)
{
    if (!cls) return "nil";
    // fixme hack rwlock_write(&runtimeLock);
    const char *name = getName(newcls(cls));
    // rwlock_unlock_write(&runtimeLock);
    return name;
}


const char *class_getName(Class cls)
{
    return _class_getName(cls);
}


Method
_class_getMethodNoSuper_nolock(Class cls, SEL sel)
{
    return (Method)getMethodNoSuper_nolock(newcls(cls), sel);
}


void
log_and_fill_cache(Class cls, Class implementer, Method meth, SEL sel)
{
#if defined(MESSAGE_LOGGING)
    BOOL cacheIt = YES;

    if (objcMsgLogEnabled) {
        cacheIt = objcMsgLogProc (_class_isMetaClass(implementer) ? YES : NO,
                                  _class_getName(cls),
                                  _class_getName(implementer), 
                                  sel);
    }
    if (cacheIt)
#endif
        _cache_fill (cls, meth, sel);
}


IMP lookUpMethod(Class cls, SEL sel, BOOL initialize, BOOL cache, id inst)
{
    Class curClass;
    IMP methodPC = NULL;
    Method meth;
    BOOL triedResolver = NO;

    // Optimistic cache lookup
    if (cache) {
        methodPC = _cache_getImp(cls, sel);
        if (methodPC) return methodPC;    
    }

    // realize, +initialize, and any special early exit
    methodPC = prepareForMethodLookup(cls, sel, initialize, inst);
    if (methodPC) return methodPC;


    // The lock is held to make method-lookup + cache-fill atomic 
    // with respect to method addition. Otherwise, a category could 
    // be added but ignored indefinitely because the cache was re-filled 
    // with the old value after the cache flush on behalf of the category.
retry:
    lockForMethodLookup();

    // Ignore GC selectors
    if (ignoreSelector(sel)) {
        methodPC = _cache_addIgnoredEntry(cls, sel);
        goto done;
    }

    // Try this class's cache.

    methodPC = _cache_getImp(cls, sel);
    if (methodPC) goto done;

    // Try this class's method lists.

    meth = _class_getMethodNoSuper_nolock(cls, sel);
    if (meth) {
        log_and_fill_cache(cls, cls, meth, sel);
        methodPC = method_getImplementation(meth);
        goto done;
    }

    // Try superclass caches and method lists.

    curClass = cls;
    while ((curClass = _class_getSuperclass(curClass))) {
        // Superclass cache.
        meth = _cache_getMethod(curClass, sel, _objc_msgForward_internal);
        if (meth) {
            if (meth != (Method)1) {
                // Found the method in a superclass. Cache it in this class.
                log_and_fill_cache(cls, curClass, meth, sel);
                methodPC = method_getImplementation(meth);
                goto done;
            }
            else {
                // Found a forward:: entry in a superclass.
                // Stop searching, but don't cache yet; call method 
                // resolver for this class first.
                break;
            }
        }

        // Superclass method list.
        meth = _class_getMethodNoSuper_nolock(curClass, sel);
        if (meth) {
            log_and_fill_cache(cls, curClass, meth, sel);
            methodPC = method_getImplementation(meth);
            goto done;
        }
    }

    // No implementation found. Try method resolver once.

    if (!triedResolver) {
        unlockForMethodLookup();
        _class_resolveMethod(cls, sel);
        // Don't cache the result; we don't hold the lock so it may have 
        // changed already. Re-do the search from scratch instead.
        triedResolver = YES;
        goto retry;
    }

    // No implementation found, and method resolver didn't help. 
    // Use forwarding.

    _cache_addForwardEntry(cls, sel);
    methodPC = _objc_msgForward_internal;

done:
    unlockForMethodLookup();

    // paranoia: look for ignored selectors with non-ignored implementations
    assert(!(ignoreSelector(sel)  &&  methodPC != (IMP)&_objc_ignored_method));

    return methodPC;
}


typedef struct {
    category_t *cat;
    BOOL fromBundle;
} category_pair_t;

typedef struct {
    uint32_t count;
    category_pair_t list[0];  // variable-size
} category_list;


static NXMapTable *unattachedCategories(void)
{
    rwlock_assert_writing(&runtimeLock);

    static NXMapTable *category_map = NULL;

    if (category_map) return category_map;

    // fixme initial map size
    category_map = NXCreateMapTableFromZone(NXPtrValueMapPrototype, 16, 
                                            _objc_internal_zone());

    return category_map;
}


static category_list *unattachedCategoriesForClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    return (category_list *)NXMapRemove(unattachedCategories(), cls);
}


static void removeSubclass(class_t *supercls, class_t *subcls)
{
    rwlock_assert_writing(&runtimeLock);
    assert(isRealized(supercls));
    assert(isRealized(subcls));
    assert(getSuperclass(subcls) == supercls);

    class_t **cp;
    for (cp = &supercls->data()->firstSubclass; 
         *cp  &&  *cp != subcls; 
         cp = &(*cp)->data()->nextSiblingClass)
        ;
    assert(*cp == subcls);
    *cp = subcls->data()->nextSiblingClass;
}


static void removeNamedClass(class_t *cls, const char *name)
{
    rwlock_assert_writing(&runtimeLock);
    assert(!(cls->data()->flags & RO_META));
#if SUPPORT_DEBUGGER_MODE
    if (cls == NXMapGet(gdb_objc_realized_classes, name)) {
        NXMapRemove(gdb_objc_realized_classes, name);
    } else {
        // cls has a name collision with another class - don't remove the other
    }
#endif
}


static NXHashTable *realized_class_hash = NULL;

static NXHashTable *realizedClasses(void)
{    
    rwlock_assert_locked(&runtimeLock);

    // allocated in _read_images
    assert(realized_class_hash);

    return realized_class_hash;
}


static void removeRealizedClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    if (isRealized(cls)) {
        assert(!isMetaClass(cls));
        NXHashRemove(realizedClasses(), cls);
        objc_removeRegisteredClass((Class)cls);
    }
}


static NXMapTable *nonmeta_class_map = NULL;
static NXMapTable *nonMetaClasses(void)
{
    rwlock_assert_locked(&runtimeLock);

    if (nonmeta_class_map) return nonmeta_class_map;

    // nonmeta_class_map is typically small
    INIT_ONCE_PTR(nonmeta_class_map, 
                  NXCreateMapTableFromZone(NXPtrValueMapPrototype, 32, 
                                           _objc_internal_zone()), 
                  NXFreeMapTable(v));

    return nonmeta_class_map;
}


static void removeNonMetaClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    NXMapRemove(nonMetaClasses(), cls->isa);
}


static NXHashTable *realized_metaclass_hash = NULL;
static NXHashTable *realizedMetaclasses(void)
{    
    rwlock_assert_locked(&runtimeLock);

    // allocated in _read_images
    assert(realized_metaclass_hash);

    return realized_metaclass_hash;
}


static void removeRealizedMetaclass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    if (isRealized(cls)) {
        assert(isMetaClass(cls));
        NXHashRemove(realizedMetaclasses(), cls);
    }
}


static void detach_class(class_t *cls, BOOL isMeta)
{
    rwlock_assert_writing(&runtimeLock);

    // categories not yet attached to this class
    category_list *cats;
    cats = unattachedCategoriesForClass(cls);
    if (cats) free(cats);

    // superclass's subclass list
    if (isRealized(cls)) {
        class_t *supercls = getSuperclass(cls);
        if (supercls) {
            removeSubclass(supercls, cls);
        }
    }

    // class tables and +load queue
    if (!isMeta) {
        removeNamedClass(cls, getName(cls));
        removeRealizedClass(cls);
        removeNonMetaClass(cls);
    } else {
        removeRealizedMetaclass(cls);
    }
}


static void removeUnattachedCategoryForClass(category_t *cat, class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);

    // DO NOT use cat->cls! cls may be cat->cls->isa instead
    NXMapTable *cats = unattachedCategories();
    category_list *list;

    list = (category_list *)NXMapGet(cats, cls);
    if (!list) return;

    uint32_t i;
    for (i = 0; i < list->count; i++) {
        if (list->list[i].cat == cat) {
            // shift entries to preserve list order
            memmove(&list->list[i], &list->list[i+1], 
                    (list->count-i-1) * sizeof(list->list[i]));
            list->count--;
            return;
        }
    }
}


typedef struct chained_property_list {
    struct chained_property_list *next;
    uint32_t count;
    property_t list[0];  // variable-size
} chained_property_list;


static void try_free(const void *p)
{
    if (p && malloc_size(p)) free((void *)p);
}


static ivar_t *ivar_list_nth(const ivar_list_t *ilist, uint32_t i)
{
    return (ivar_t *)(i*ilist->entsize + (char *)&ilist->first);
}


static void free_class(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);

    if (! isRealized(cls)) return;

    uint32_t i;
    
    // Dereferences the cache contents; do this before freeing methods
    if (cls->cache != (Cache)&_objc_empty_cache) _cache_free(cls->cache);

    FOREACH_METHOD_LIST(mlist, cls, {
        for (i = 0; i < mlist->count; i++) {
            method_t *m = method_list_nth(mlist, i);
            try_free(m->types);
        }
        try_free(mlist);
    });
    if (cls->data()->flags & RW_METHOD_ARRAY) {
        try_free(cls->data()->method_lists);
    }
    
    const ivar_list_t *ilist = cls->data()->ro->ivars;
    if (ilist) {
        for (i = 0; i < ilist->count; i++) {
            const ivar_t *ivar = ivar_list_nth(ilist, i);
            try_free(ivar->offset);
            try_free(ivar->name);
            try_free(ivar->type);
        }
        try_free(ilist);
    }
    
    const protocol_list_t **plistp;
    for (plistp = cls->data()->protocols; plistp && *plistp; plistp++) {
        try_free(*plistp);
    }
    try_free(cls->data()->protocols);
    
    const chained_property_list *proplist = cls->data()->properties;
    while (proplist) {
        for (i = 0; i < proplist->count; i++) {
            const property_t *prop = proplist->list+i;
            try_free(prop->name);
            try_free(prop->attributes);
        }
        {
            const chained_property_list *temp = proplist;
            proplist = proplist->next;
            try_free(temp);
        }
    }
    
    if (cls->vtable != &_objc_empty_vtable  &&  
        cls->data()->flags & RW_SPECIALIZED_VTABLE) try_free(cls->vtable);
    try_free(cls->data()->ro->ivarLayout);
    try_free(cls->data()->ro->weakIvarLayout);
    try_free(cls->data()->ro->name);
    try_free(cls->data()->ro);
    try_free(cls->data());
    try_free(cls);
}


void _unload_image(header_info *hi)
{
    size_t count, i;

    recursive_mutex_assert_locked(&loadMethodLock);
    rwlock_assert_writing(&runtimeLock);

    // Unload unattached categories and categories waiting for +load.

    category_t **catlist = _getObjc2CategoryList(hi, &count);
    for (i = 0; i < count; i++) {
        category_t *cat = catlist[i];
        if (!cat) continue;  // category for ignored weak-linked class
        class_t *cls = remapClass(cat->cls);
        assert(cls);  // shouldn't have live category for dead class

        // fixme for MH_DYLIB cat's class may have been unloaded already

        // unattached list
        removeUnattachedCategoryForClass(cat, cls);

        // +load queue
        remove_category_from_loadable_list((Category)cat);
    }

    // Unload classes.

    classref_t *classlist = _getObjc2ClassList(hi, &count);

    // First detach classes from each other. Then free each class.
    // This avoid bugs where this loop unloads a subclass before its superclass

    for (i = 0; i < count; i++) {
        class_t *cls = remapClass(classlist[i]);
        if (cls) {
            remove_class_from_loadable_list((Class)cls);
            detach_class(cls->isa, YES);
            detach_class(cls, NO);
        }
    }
    
    for (i = 0; i < count; i++) {
        class_t *cls = remapClass(classlist[i]);
        if (cls) {
            free_class(cls->isa);
            free_class(cls);
        }
    }
    
    // XXX FIXME -- Clean up protocols:
    // <rdar://problem/9033191> Support unloading protocols at dylib/image unload time

    // fixme DebugUnload
}


BOOL 
_class_isLoadable(Class cls)
{
    assert(isRealized(newcls(cls)));
    return YES;  // any class registered for +load is definitely loadable
}


IMP
_class_getLoadMethod(Class cls_gen)
{
    rwlock_assert_locked(&runtimeLock);

    class_t *cls = newcls(cls_gen);
    const method_list_t *mlist;
    uint32_t i;

    assert(isRealized(cls));
    assert(isRealized(cls->isa));
    assert(!isMetaClass(cls));
    assert(isMetaClass(cls->isa));

    mlist = cls->isa->data()->ro->baseMethods;
    if (mlist) for (i = 0; i < mlist->count; i++) {
        method_t *m = method_list_nth(mlist, i);
        if (0 == strcmp((const char *)m->name, "load")) {
            return m->imp;
        }
    }

    return NULL;
}


IMP
_category_getLoadMethod(Category cat)
{
    rwlock_assert_locked(&runtimeLock);

    const method_list_t *mlist;
    uint32_t i;

    mlist = newcategory(cat)->classMethods;
    if (mlist) for (i = 0; i < mlist->count; i++) {
        method_t *m = method_list_nth(mlist, i);
        if (0 == strcmp((const char *)m->name, "load")) {
            return m->imp;
        }
    }

    return NULL;
}


header_info *FirstHeader = 0;  // NULL means empty list
header_info *LastHeader  = 0;  // NULL means invalid; recompute it
int HeaderCount = 0;


void appendHeader(header_info *hi)
{
    // Add the header to the header list. 
    // The header is appended to the list, to preserve the bottom-up order.
    HeaderCount++;
    hi->next = NULL;
    if (!FirstHeader) {
        // list is empty
        FirstHeader = LastHeader = hi;
    } else {
        if (!LastHeader) {
            // list is not empty, but LastHeader is invalid - recompute it
            LastHeader = FirstHeader;
            while (LastHeader->next) LastHeader = LastHeader->next;
        }
        // LastHeader is now valid
        LastHeader->next = hi;
        LastHeader = hi;
    }
}


void removeHeader(header_info *hi)
{
    header_info **hiP;

    for (hiP = &FirstHeader; *hiP != NULL; hiP = &(**hiP).next) {
        if (*hiP == hi) {
            header_info *deadHead = *hiP;

            // Remove from the linked list (updating FirstHeader if necessary).
            *hiP = (**hiP).next;
            
            // Update LastHeader if necessary.
            if (LastHeader == deadHead) {
                LastHeader = NULL;  // will be recomputed next time it's used
            }

            HeaderCount--;
            break;
        }
    }
}


void
unmap_image_nolock(const struct mach_header *mh)
{
    if (PrintImages) {
        _objc_inform("IMAGES: processing 1 newly-unmapped image...\n");
    }

    header_info *hi;
    
    // Find the runtime's header_info struct for the image
    for (hi = FirstHeader; hi != NULL; hi = hi->next) {
        if (hi->mhdr == (const headerType *)mh) {
            break;
        }
    }

    if (!hi) return;

    if (PrintImages) { 
        _objc_inform("IMAGES: unloading image for %s%s%s%s\n", 
                     hi->fname, 
                     hi->mhdr->filetype == MH_BUNDLE ? " (bundle)" : "", 
                     _objcHeaderIsReplacement(hi) ? " (replacement)" : "", 
                     _gcForHInfo2(hi));
    }

    _unload_image(hi);

    // Remove header_info from header list
    removeHeader(hi);
    _free_internal(hi);
}


void
unmap_image(const struct mach_header *mh, intptr_t vmaddr_slide)
{
    recursive_mutex_lock(&loadMethodLock);
    rwlock_write(&runtimeLock);

    unmap_image_nolock(mh);

    rwlock_unlock_write(&runtimeLock);
    recursive_mutex_unlock(&loadMethodLock);
}


BOOL 
load_images_nolock(enum dyld_image_states state,uint32_t infoCount,
                   const struct dyld_image_info infoList[])
{
    BOOL found = NO;
    uint32_t i;

    i = infoCount;
    while (i--) {
        header_info *hi;
        for (hi = FirstHeader; hi != NULL; hi = hi->next) {
            const headerType *mhdr = (headerType*)infoList[i].imageLoadAddress;
            if (hi->mhdr == mhdr) {
                prepare_load_methods(hi);
                found = YES;
            }
        }
    }

    return found;
}


static void schedule_class_load(class_t *cls)
{
    if (!cls) return;
    assert(isRealized(cls));  // _read_images should realize

    if (cls->data()->flags & RW_LOADED) return;

    // Ensure superclass-first ordering
    schedule_class_load(getSuperclass(cls));

    add_class_to_loadable_list((Class)cls);
    changeInfo(cls, RW_LOADED, 0); 
}


static class_t *realizeClass(class_t *cls);


void prepare_load_methods(header_info *hi)
{
    size_t count, i;

    rwlock_assert_writing(&runtimeLock);

    classref_t *classlist = 
        _getObjc2NonlazyClassList(hi, &count);
    for (i = 0; i < count; i++) {
        schedule_class_load(remapClass(classlist[i]));
    }

    category_t **categorylist = _getObjc2NonlazyCategoryList(hi, &count);
    for (i = 0; i < count; i++) {
        category_t *cat = categorylist[i];
        class_t *cls = remapClass(cat->cls);
        if (!cls) continue;  // category for ignored weak-linked class
        realizeClass(cls);
        assert(isRealized(cls->isa));
        add_category_to_loadable_list((Category)cat);
    }
}


const char *
load_images(enum dyld_image_states state, uint32_t infoCount,
            const struct dyld_image_info infoList[])
{
    BOOL found;

    recursive_mutex_lock(&loadMethodLock);

    // Discover load methods
    rwlock_write(&runtimeLock);
    found = load_images_nolock(state, infoCount, infoList);
    rwlock_unlock_write(&runtimeLock);

    // Call +load methods (without runtimeLock - re-entrant)
    if (found) {
        call_load_methods();
    }

    recursive_mutex_unlock(&loadMethodLock);

    return NULL;
}


BOOL bad_magic(const headerType *mhdr)
{
    return (mhdr->magic != MH_MAGIC  &&  mhdr->magic != MH_MAGIC_64  &&  
            mhdr->magic != MH_CIGAM  &&  mhdr->magic != MH_CIGAM_64);
}


static header_info * addHeader(const headerType *mhdr)
{
    header_info *hi;

    if (bad_magic(mhdr)) return NULL;

#if __OBJC2__
    // Look for hinfo from the dyld shared cache.
    hi = preoptimizedHinfoForHeader(mhdr);
    if (hi) {
        // Found an hinfo in the dyld shared cache.

        // Weed out duplicates.
        if (hi->loaded) {
            return NULL;
        }

        // Initialize fields not set by the shared cache
        // hi->next is set by appendHeader
        hi->fname = dyld_image_path_containing_address(hi->mhdr);
        hi->loaded = true;
        hi->inSharedCache = true;

        if (PrintPreopt) {
            _objc_inform("PREOPTIMIZATION: honoring preoptimized header info at %p for %s", hi, hi->fname);
        }

# if !NDEBUG
        // Verify image_info
        size_t info_size = 0;
        const objc_image_info *image_info = _getObjcImageInfo(mhdr,&info_size);
        assert(image_info == hi->info);
# endif
    }
    else 
#endif
    {
        // Didn't find an hinfo in the dyld shared cache.

        // Weed out duplicates
        for (hi = FirstHeader; hi; hi = hi->next) {
            if (mhdr == hi->mhdr) return NULL;
        }

        // Locate the __OBJC segment
        size_t info_size = 0;
        unsigned long seg_size;
        const objc_image_info *image_info = _getObjcImageInfo(mhdr,&info_size);
        const uint8_t *objc_segment = getsegmentdata(mhdr,SEG_OBJC,&seg_size);
        if (!objc_segment  &&  !image_info) return NULL;

        // Allocate a header_info entry.
        hi = (header_info *)_calloc_internal(sizeof(header_info), 1);

        // Set up the new header_info entry.
        hi->mhdr = mhdr;
#if !__OBJC2__
        // mhdr must already be set
        hi->mod_count = 0;
        hi->mod_ptr = _getObjcModules(hi, &hi->mod_count);
#endif
        hi->info = image_info;
        hi->fname = dyld_image_path_containing_address(hi->mhdr);
        hi->loaded = true;
        hi->inSharedCache = false;
        hi->allClassesRealized = NO;
    }

    // dylibs are not allowed to unload
    // ...except those with image_info and nothing else (5359412)
    if (hi->mhdr->filetype == MH_DYLIB  &&  _hasObjcContents(hi)) {
        dlopen(hi->fname, RTLD_NOLOAD);
    }

    appendHeader(hi);
    
    return hi;
}


static NXMapTable *futureNamedClasses(void)
{
    rwlock_assert_writing(&runtimeLock);

    static NXMapTable *future_named_class_map = NULL;
    
    if (future_named_class_map) return future_named_class_map;

    // future_named_class_map is big enough for CF's classes and a few others
    future_named_class_map = 
        NXCreateMapTableFromZone(NXStrValueMapPrototype, 32,
                                 _objc_internal_zone());

    return future_named_class_map;
}


static BOOL 
missingWeakSuperclass(class_t *cls)
{
    assert(!isRealized(cls));

    if (!cls->superclass) {
        // superclass NULL. This is normal for root classes only.
        return (!(cls->data()->flags & RO_ROOT));
    } else {
        // superclass not NULL. Check if a higher superclass is missing.
        class_t *supercls = remapClass(cls->superclass);
        assert(cls != cls->superclass);
        assert(cls != supercls);
        if (!supercls) return YES;
        if (isRealized(supercls)) return NO;
        return missingWeakSuperclass(supercls);
    }
}


static void addRemappedClass(class_t *oldcls, class_t *newcls)
{
    rwlock_assert_writing(&runtimeLock);

    if (PrintFuture) {
        _objc_inform("FUTURE: using %p instead of %p for %s", 
                     oldcls, newcls, getName(oldcls));
    }

    void *old;
    old = NXMapInsert(remappedClasses(YES), oldcls, newcls);
    assert(!old);
}


static void removeFutureNamedClass(const char *name)
{
    rwlock_assert_writing(&runtimeLock);

    NXMapKeyFreeingRemove(futureNamedClasses(), name);
}


static class_ro_t *make_ro_writeable(class_rw_t *rw)
{
    rwlock_assert_writing(&runtimeLock);

    if (rw->flags & RW_COPIED_RO) {
        // already writeable, do nothing
    } else {
        class_ro_t *ro = (class_ro_t *)
            _memdup_internal(rw->ro, sizeof(*rw->ro));
        rw->ro = ro;
        rw->flags |= RW_COPIED_RO;
    }
    return (class_ro_t *)rw->ro;
}


typedef struct {
    uintptr_t *offset;
    const char *name;
    const char *type;
    uint32_t alignment;
} ivar_alignment_t;

static uint32_t ivar_alignment(const ivar_t *ivar)
{
    uint32_t alignment = ((ivar_alignment_t *)ivar)->alignment;
    if (alignment == (uint32_t)-1) alignment = (uint32_t)WORD_SHIFT;
    return 1<<alignment;
}


static void moveIvars(class_ro_t *ro, uint32_t superSize, 
                      layout_bitmap *ivarBitmap, layout_bitmap *weakBitmap)
{
    rwlock_assert_writing(&runtimeLock);

    uint32_t diff;
    uint32_t i;

    assert(superSize > ro->instanceStart);
    diff = superSize - ro->instanceStart;

    if (ro->ivars) {
        // Find maximum alignment in this class's ivars
        uint32_t maxAlignment = 1;
        for (i = 0; i < ro->ivars->count; i++) {
            ivar_t *ivar = ivar_list_nth(ro->ivars, i);
            if (!ivar->offset) continue;  // anonymous bitfield

            uint32_t alignment = ivar_alignment(ivar);
            if (alignment > maxAlignment) maxAlignment = alignment;
        }

        // Compute a slide value that preserves that alignment
        uint32_t alignMask = maxAlignment - 1;
        if (diff & alignMask) diff = (diff + alignMask) & ~alignMask;

        // Slide all of this class's ivars en masse
        for (i = 0; i < ro->ivars->count; i++) {
            ivar_t *ivar = ivar_list_nth(ro->ivars, i);
            if (!ivar->offset) continue;  // anonymous bitfield

            uint32_t oldOffset = (uint32_t)*ivar->offset;
            uint32_t newOffset = oldOffset + diff;
            *ivar->offset = newOffset;

            if (PrintIvars) {
                _objc_inform("IVARS:    offset %u -> %u for %s (size %u, align %u)", 
                             oldOffset, newOffset, ivar->name, 
                             ivar->size, ivar_alignment(ivar));
            }
        }

        // Slide GC layouts
        uint32_t oldOffset = ro->instanceStart;
        uint32_t newOffset = ro->instanceStart + diff;

        if (ivarBitmap) {
            layout_bitmap_slide(ivarBitmap, 
                                oldOffset >> WORD_SHIFT, 
                                newOffset >> WORD_SHIFT);
        }
        if (weakBitmap) {
            layout_bitmap_slide(weakBitmap, 
                                oldOffset >> WORD_SHIFT, 
                                newOffset >> WORD_SHIFT);
        }
    }

    *(uint32_t *)&ro->instanceStart += diff;
    *(uint32_t *)&ro->instanceSize += diff;

    if (!ro->ivars) {
        // No ivars slid, but superclass changed size. 
        // Expand bitmap in preparation for layout_bitmap_splat().
        if (ivarBitmap) layout_bitmap_grow(ivarBitmap, ro->instanceSize >> WORD_SHIFT);
        if (weakBitmap) layout_bitmap_grow(weakBitmap, ro->instanceSize >> WORD_SHIFT);
    }
}


static void reconcileInstanceVariables(class_t *cls, class_t *supercls) {
    class_rw_t *rw = cls->data();
    const class_ro_t *ro = rw->ro;
    
    if (supercls) {
        // Non-fragile ivars - reconcile this class with its superclass
        // Does this really need to happen for the isMETA case?
        layout_bitmap ivarBitmap;
        layout_bitmap weakBitmap;
        BOOL layoutsChanged = NO;
        BOOL mergeLayouts = UseGC;
        const class_ro_t *super_ro = supercls->data()->ro;
        
        if (DebugNonFragileIvars) {
            // Debugging: Force non-fragile ivars to slide.
            // Intended to find compiler, runtime, and program bugs.
            // If it fails with this and works without, you have a problem.
            
            // Operation: Reset everything to 0 + misalignment. 
            // Then force the normal sliding logic to push everything back.
            
            // Exceptions: root classes, metaclasses, *NSCF* classes, 
            // __CF* classes, NSConstantString, NSSimpleCString
            
            // (already know it's not root because supercls != nil)
            if (!strstr(getName(cls), "NSCF")  &&  
                0 != strncmp(getName(cls), "__CF", 4)  &&  
                0 != strcmp(getName(cls), "NSConstantString")  &&  
                0 != strcmp(getName(cls), "NSSimpleCString")) 
            {
                uint32_t oldStart = ro->instanceStart;
                uint32_t oldSize = ro->instanceSize;
                class_ro_t *ro_w = make_ro_writeable(rw);
                ro = rw->ro;
                
                // Find max ivar alignment in class.
                // default to word size to simplify ivar update
                uint32_t alignment = 1<<WORD_SHIFT;
                if (ro->ivars) {
                    uint32_t i;
                    for (i = 0; i < ro->ivars->count; i++) {
                        ivar_t *ivar = ivar_list_nth(ro->ivars, i);
                        if (ivar_alignment(ivar) > alignment) {
                            alignment = ivar_alignment(ivar);
                        }
                    }
                }
                uint32_t misalignment = ro->instanceStart % alignment;
                uint32_t delta = ro->instanceStart - misalignment;
                ro_w->instanceStart = misalignment;
                ro_w->instanceSize -= delta;
                
                if (PrintIvars) {
                    _objc_inform("IVARS: DEBUG: forcing ivars for class '%s' "
                                 "to slide (instanceStart %zu -> %zu)", 
                                 getName(cls), (size_t)oldStart, 
                                 (size_t)ro->instanceStart);
                }
                
                if (ro->ivars) {
                    uint32_t i;
                    for (i = 0; i < ro->ivars->count; i++) {
                        ivar_t *ivar = ivar_list_nth(ro->ivars, i);
                        if (!ivar->offset) continue;  // anonymous bitfield
                        *ivar->offset -= delta;
                    }
                }
                
                if (mergeLayouts) {
                    layout_bitmap layout;
                    if (ro->ivarLayout) {
                        layout = layout_bitmap_create(ro->ivarLayout, 
                                                      oldSize, oldSize, NO);
                        layout_bitmap_slide_anywhere(&layout, 
                                                     delta >> WORD_SHIFT, 0);
                        ro_w->ivarLayout = layout_string_create(layout);
                        layout_bitmap_free(layout);
                    }
                    if (ro->weakIvarLayout) {
                        layout = layout_bitmap_create(ro->weakIvarLayout, 
                                                      oldSize, oldSize, YES);
                        layout_bitmap_slide_anywhere(&layout, 
                                                     delta >> WORD_SHIFT, 0);
                        ro_w->weakIvarLayout = layout_string_create(layout);
                        layout_bitmap_free(layout);
                    }
                }
            }
        }
        
        // fixme can optimize for "class has no new ivars", etc
        // WARNING: gcc c++ sets instanceStart/Size=0 for classes with  
        //   no local ivars, but does provide a layout bitmap. 
        //   Handle that case specially so layout_bitmap_create doesn't die
        //   The other ivar sliding code below still works fine, and 
        //   the final result is a good class.
        if (ro->instanceStart == 0  &&  ro->instanceSize == 0) {
            // We can't use ro->ivarLayout because we don't know
            // how long it is. Force a new layout to be created.
            if (PrintIvars) {
                _objc_inform("IVARS: instanceStart/Size==0 for class %s; "
                             "disregarding ivar layout", ro->name);
            }
            ivarBitmap = layout_bitmap_create_empty(super_ro->instanceSize, NO);
            weakBitmap = layout_bitmap_create_empty(super_ro->instanceSize, YES);
            layoutsChanged = YES;
        } else {
            ivarBitmap = 
            layout_bitmap_create(ro->ivarLayout, 
                                 ro->instanceSize, 
                                 ro->instanceSize, NO);
            weakBitmap = 
            layout_bitmap_create(ro->weakIvarLayout, 
                                 ro->instanceSize,
                                 ro->instanceSize, YES);
        }
        
        if (ro->instanceStart < super_ro->instanceSize) {
            // Superclass has changed size. This class's ivars must move.
            // Also slide layout bits in parallel.
            // This code is incapable of compacting the subclass to 
            //   compensate for a superclass that shrunk, so don't do that.
            if (PrintIvars) {
                _objc_inform("IVARS: sliding ivars for class %s "
                             "(superclass was %u bytes, now %u)", 
                             ro->name, ro->instanceStart, 
                             super_ro->instanceSize);
            }
            class_ro_t *ro_w = make_ro_writeable(rw);
            ro = rw->ro;
            moveIvars(ro_w, super_ro->instanceSize, 
                      mergeLayouts ? &ivarBitmap : NULL, mergeLayouts ? &weakBitmap : NULL);
#if SUPPORT_DEBUGGER_MODE
            gdb_objc_class_changed((Class)cls, OBJC_CLASS_IVARS_CHANGED, ro->name);
#endif
            layoutsChanged = mergeLayouts;
        } 
        
        if (mergeLayouts) {
            // Check superclass's layout against this class's layout.
            // This needs to be done even if the superclass is not bigger.
            layout_bitmap superBitmap = layout_bitmap_create(super_ro->ivarLayout, 
                                                             super_ro->instanceSize, 
                                                             super_ro->instanceSize, NO);
            layoutsChanged |= layout_bitmap_splat(ivarBitmap, superBitmap, 
                                                  ro->instanceStart);
            layout_bitmap_free(superBitmap);
            
            // check the superclass' weak layout.
            superBitmap = layout_bitmap_create(super_ro->weakIvarLayout, 
                                               super_ro->instanceSize, 
                                               super_ro->instanceSize, YES);
            layoutsChanged |= layout_bitmap_splat(weakBitmap, superBitmap, 
                                                  ro->instanceStart);
            layout_bitmap_free(superBitmap);
        }
        
        if (layoutsChanged) {
            // Rebuild layout strings. 
            if (PrintIvars) {
                _objc_inform("IVARS: gc layout changed for class %s",
                             ro->name);
            }
            class_ro_t *ro_w = make_ro_writeable(rw);
            ro = rw->ro;
            if (DebugNonFragileIvars) {
                try_free(ro_w->ivarLayout);
                try_free(ro_w->weakIvarLayout);
            }
            ro_w->ivarLayout = layout_string_create(ivarBitmap);
            ro_w->weakIvarLayout = layout_string_create(weakBitmap);
        }
        
        layout_bitmap_free(ivarBitmap);
        layout_bitmap_free(weakBitmap);
    }
}


static void changeInfo(class_t *cls, unsigned int set, unsigned int clear)
{
    uint32_t oldf, newf;

    assert(isFuture(cls)  ||  isRealized(cls));

    do {
        oldf = cls->data()->flags;
        newf = (oldf | set) & ~clear;
    } while (!OSAtomicCompareAndSwap32Barrier(oldf, newf, (volatile int32_t *)&cls->data()->flags));
}


static void addSubclass(class_t *supercls, class_t *subcls)
{
    rwlock_assert_writing(&runtimeLock);

    if (supercls  &&  subcls) {
        assert(isRealized(supercls));
        assert(isRealized(subcls));
        subcls->data()->nextSiblingClass = supercls->data()->firstSubclass;
        supercls->data()->firstSubclass = subcls;

        if (supercls->data()->flags & RW_HAS_CXX_STRUCTORS) {
            subcls->data()->flags |= RW_HAS_CXX_STRUCTORS;
        }

        if (supercls->hasCustomRR()) {
            subcls->setHasCustomRR(true);
        }

        if (supercls->hasCustomAWZ()) {
            subcls->setHasCustomAWZ(true);
        }
    }
}


static BOOL isBundleClass(class_t *cls)
{
    return (cls->data()->ro->flags & RO_FROM_BUNDLE) ? YES : NO;
}


static IMP 
_method_getImplementation(method_t *m)
{
    if (!m) return NULL;
    return m->imp;
}


IMP 
method_getImplementation(Method m)
{
    return _method_getImplementation(newmethod(m));
}


static bool isRRSelector(SEL sel)
{
    return (sel == SEL_retain  ||  sel == SEL_release  ||  
            sel == SEL_autorelease || sel == SEL_retainCount);
}


static class_t *classNSObject(void)
{
    extern class_t OBJC_CLASS_$_NSObject;
    return &OBJC_CLASS_$_NSObject;
}


static bool isAWZSelector(SEL sel)
{
    return (sel == SEL_allocWithZone);
}


static void
updateCustomRR_AWZ(class_t *cls, method_t *meth)
{
    // In almost all cases, IMP swizzling does not affect custom RR/AWZ bits. 
    // The class is already marked for custom RR/AWZ, so changing the IMP 
    // does not transition from non-custom to custom.
    // 
    // The only cases where IMP swizzling can affect the RR/AWZ bits is 
    // if the swizzled method is one of the methods that is assumed to be 
    // non-custom. These special cases come from attachMethodLists(). 
    // We look for such cases here if we do not know the affected class.

    if (isRRSelector(meth->name)) {
        if (cls) {
            cls->setHasCustomRR();
        } else {
            // Don't know the class. 
            // The only special case is class NSObject.
            FOREACH_METHOD_LIST(mlist, classNSObject(), {
                for (uint32_t i = 0; i < mlist->count; i++) {
                    if (meth == method_list_nth(mlist, i)) {
                        // Yep, they're swizzling NSObject.
                        classNSObject()->setHasCustomRR();
                        return;
                    }
                }
            });
        }
    }
    else if (isAWZSelector(meth->name)) {
        if (cls) {
            cls->setHasCustomAWZ();
        } else {
            // Don't know the class. 
            // The only special case is metaclass NSObject.
            FOREACH_METHOD_LIST(mlist, classNSObject()->isa, {
                for (uint32_t i = 0; i < mlist->count; i++) {
                    if (meth == method_list_nth(mlist, i)) {
                        // Yep, they're swizzling metaclass NSObject.
                        classNSObject()->isa->setHasCustomRR();
                        return;
                    }
                }
            });
        }
    }
}


static IMP
_method_setImplementation(class_t *cls, method_t *m, IMP imp)
{
    rwlock_assert_writing(&runtimeLock);

    if (!m) return NULL;
    if (!imp) return NULL;

    if (ignoreSelector(m->name)) {
        // Ignored methods stay ignored
        return m->imp;
    }

    IMP old = _method_getImplementation(m);
    m->imp = imp;

    // No cache flushing needed - cache contains Methods not IMPs.
    
    // vtable and RR/AWZ updates are slow if cls is NULL (i.e. unknown)
    // fixme build list of classes whose Methods are known externally?

#if SUPPORT_VTABLE
    if (vtable_containsSelector(m->name)) {
        flushVtables(cls);
    }
#endif

    // Catch changes to retain/release and allocWithZone implementations
    updateCustomRR_AWZ(cls, m);

    // fixme update monomorphism if necessary

    return old;
}


static void
attachMethodLists(class_t *cls, method_list_t **addedLists, int addedCount, 
                  BOOL baseMethods, BOOL methodsFromBundle, 
                  BOOL *inoutVtablesAffected);


static void flushCaches(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);

    FOREACH_REALIZED_CLASS_AND_SUBCLASS(c, cls, {
        flush_cache((Class)c);
    });
}


static IMP
addMethod(class_t *cls, SEL name, IMP imp, const char *types, BOOL replace)
{
    IMP result = NULL;

    rwlock_assert_writing(&runtimeLock);

    assert(types);
    assert(isRealized(cls));

    method_t *m;
    if ((m = getMethodNoSuper_nolock(cls, name))) {
        // already exists
        if (!replace) {
            result = _method_getImplementation(m);
        } else {
            result = _method_setImplementation(cls, m, imp);
        }
    } else {
        // fixme optimize
        method_list_t *newlist;
        newlist = (method_list_t *)_calloc_internal(sizeof(*newlist), 1);
        newlist->entsize_NEVER_USE = (uint32_t)sizeof(method_t) | fixed_up_method_list;
        newlist->count = 1;
        newlist->first.name = name;
        newlist->first.types = strdup(types);
        if (!ignoreSelector(name)) {
            newlist->first.imp = imp;
        } else {
            newlist->first.imp = (IMP)&_objc_ignored_method;
        }

        BOOL vtablesAffected = NO;
        attachMethodLists(cls, &newlist, 1, NO, NO, &vtablesAffected);
        flushCaches(cls);
#if SUPPORT_VTABLE
        if (vtablesAffected) flushVtables(cls);
#endif

        result = NULL;
    }

    return result;
}


static void 
attachCategoryMethods(class_t *cls, category_list *cats, 
                      BOOL *inoutVtablesAffected);

static chained_property_list *
buildPropertyList(const property_list_t *plist, category_list *cats, BOOL isMeta);

static const protocol_list_t **
buildProtocolList(category_list *cats, const protocol_list_t *base, 
                  const protocol_list_t **protos);

static void methodizeClass(class_t *cls)
{
    category_list *cats;
    BOOL isMeta;

    rwlock_assert_writing(&runtimeLock);

    isMeta = isMetaClass(cls);

    // Methodizing for the first time
    if (PrintConnecting) {
        _objc_inform("CLASS: methodizing class '%s' %s", 
                     getName(cls), isMeta ? "(meta)" : "");
    }
    
    // Build method and protocol and property lists.
    // Include methods and protocols and properties from categories, if any

    attachMethodLists(cls, (method_list_t **)&cls->data()->ro->baseMethods, 1, 
                      YES, isBundleClass(cls), NULL);

    // Root classes get bonus method implementations if they don't have 
    // them already. These apply before category replacements.

    if (cls->isRootMetaclass()) {
        // root metaclass
        addMethod(cls, SEL_initialize, (IMP)&objc_noop_imp, "", NO);
    }

    cats = unattachedCategoriesForClass(cls);
    attachCategoryMethods(cls, cats, NULL);

    if (cats  ||  cls->data()->ro->baseProperties) {
        cls->data()->properties = 
            buildPropertyList(cls->data()->ro->baseProperties, cats, isMeta);
    }
    
    if (cats  ||  cls->data()->ro->baseProtocols) {
        cls->data()->protocols = 
            buildProtocolList(cats, cls->data()->ro->baseProtocols, NULL);
    }

    if (PrintConnecting) {
        uint32_t i;
        if (cats) {
            for (i = 0; i < cats->count; i++) {
                _objc_inform("CLASS: attached category %c%s(%s)", 
                             isMeta ? '+' : '-', 
                             getName(cls), cats->list[i].cat->name);
            }
        }
    }
    
    if (cats) _free_internal(cats);

    // No vtable until +initialize completes
    assert(cls->vtable == &_objc_empty_vtable);

#ifndef NDEBUG
    // Debug: sanity-check all SELs; log method list contents
    FOREACH_METHOD_LIST(mlist, cls, {
        method_list_t::method_iterator iter = mlist->begin();
        method_list_t::method_iterator end = mlist->end();
        for ( ; iter != end; ++iter) {
            if (PrintConnecting) {
                _objc_inform("METHOD %c[%s %s]", isMeta ? '+' : '-', 
                             getName(cls), sel_getName(iter->name));
            }
            assert(ignoreSelector(iter->name)  ||  sel_registerName(sel_getName(iter->name))==iter->name); 
        }
    });
#endif
}


static void addRealizedClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    void *old;
    old = NXHashInsert(realizedClasses(), cls);
    objc_addRegisteredClass((Class)cls);
    assert(!isMetaClass(cls));
    assert(!old);
}


static void addRealizedMetaclass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    void *old;
    old = NXHashInsert(realizedMetaclasses(), cls);
    assert(isMetaClass(cls));
    assert(!old);
}


static class_t *realizeClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);

    const class_ro_t *ro;
    class_rw_t *rw;
    class_t *supercls;
    class_t *metacls;
    BOOL isMeta;

    if (!cls) return NULL;
    if (isRealized(cls)) return cls;
    assert(cls == remapClass(cls));

    ro = (const class_ro_t *)cls->data();
    if (ro->flags & RO_FUTURE) {
        // This was a future class. rw data is already allocated.
        rw = cls->data();
        ro = cls->data()->ro;
        changeInfo(cls, RW_REALIZED, RW_FUTURE);
    } else {
        // Normal class. Allocate writeable class data.
        rw = (class_rw_t *)_calloc_internal(sizeof(class_rw_t), 1);
        rw->ro = ro;
        rw->flags = RW_REALIZED;
        cls->setData(rw);
    }

    isMeta = (ro->flags & RO_META) ? YES : NO;

    rw->version = isMeta ? 7 : 0;  // old runtime went up to 6

    if (PrintConnecting) {
        _objc_inform("CLASS: realizing class '%s' %s %p %p", 
                     ro->name, isMeta ? "(meta)" : "", cls, ro);
    }

    // Realize superclass and metaclass, if they aren't already.
    // This needs to be done after RW_REALIZED is set above, for root classes.
    supercls = realizeClass(remapClass(cls->superclass));
    metacls = realizeClass(remapClass(cls->isa));

    // Check for remapped superclass and metaclass
    if (supercls != cls->superclass) {
        cls->superclass = supercls;
    }
    if (metacls != cls->isa) {
        cls->isa = metacls;
    }

    /* debug: print them all
    if (ro->ivars) {
        uint32_t i;
        for (i = 0; i < ro->ivars->count; i++) {
            ivar_t *ivar = ivar_list_nth(ro->ivars, i);
            if (!ivar->offset) continue;  // anonymous bitfield

            _objc_inform("IVARS: %s.%s (offset %u, size %u, align %u)", 
                         ro->name, ivar->name, 
                         *ivar->offset, ivar->size, ivar_alignment(ivar));
        }
    }
    */

    // Reconcile instance variable offsets / layout.
    if (!isMeta) reconcileInstanceVariables(cls, supercls);

    // Copy some flags from ro to rw
    if (ro->flags & RO_HAS_CXX_STRUCTORS) rw->flags |= RW_HAS_CXX_STRUCTORS;

    // Connect this class to its superclass's subclass lists
    if (supercls) {
        addSubclass(supercls, cls);
    }

    // Attach categories
    methodizeClass(cls);

    if (!isMeta) {
        addRealizedClass(cls);
    } else {
        addRealizedMetaclass(cls);
    }

    return cls;
}


static void addNonMetaClass(class_t *cls)
{
    rwlock_assert_writing(&runtimeLock);
    void *old;
    old = NXMapInsert(nonMetaClasses(), cls->isa, cls);

    assert(isRealized(cls));
    assert(isRealized(cls->isa));
    assert(!isMetaClass(cls));
    assert(isMetaClass(cls->isa));
    assert(!old);
}


static class_t *getNonMetaClass(class_t *metacls, id inst)
{
    static int total, slow, memo;
    rwlock_assert_locked(&runtimeLock);

    realizeClass(metacls);

    total++;

    // return cls itself if it's already a non-meta class
    if (!isMetaClass(metacls)) return metacls;

    // metacls really is a metaclass

    // special case for root metaclass
    // where inst == inst->isa == metacls is possible
    if (metacls->isa == metacls) {
        class_t *cls = metacls->superclass;
        assert(isRealized(cls));
        assert(!isMetaClass(cls));
        assert(cls->isa == metacls);
        if (cls->isa == metacls) return cls;
    }

    // use inst if available
    if (inst) {
        class_t *cls = (class_t *)inst;
        realizeClass(cls);
        // cls may be a subclass - find the real class for metacls
        while (cls  &&  cls->isa != metacls) {
            cls = cls->superclass;
            realizeClass(cls);
        }
        if (cls) {
            assert(!isMetaClass(cls));
            assert(cls->isa == metacls);
            return cls;
        }
#if !NDEBUG
        _objc_fatal("cls is not an instance of metacls");
#else
        // release build: be forgiving and fall through to slow lookups
#endif
    }

    // try memoized table
    class_t *cls = (class_t *)NXMapGet(nonMetaClasses(), metacls);
    if (cls) {
        memo++;
        if (PrintInitializing) {
            _objc_inform("INITIALIZE: %d/%d (%g%%) memoized metaclass lookups",
                         memo, total, memo*100.0/total);
        }

        assert(isRealized(cls));
        assert(!isMetaClass(cls));
        assert(cls->isa == metacls);
        return cls;
    }

    // try slow lookup
    slow++;
    if (PrintInitializing) {
        _objc_inform("INITIALIZE: %d/%d (%g%%) slow metaclass lookups", 
                     slow, total, slow*100.0/total);
    }

    for (header_info *hi = FirstHeader; hi; hi = hi->next) {
        size_t count;
        classref_t *classlist = _getObjc2ClassList(hi, &count);
        for (size_t i = 0; i < count; i++) {
            cls = remapClass(classlist[i]);
            if (cls  &&  cls->isa == metacls) {
                // memoize result
                realizeClass(cls);
                addNonMetaClass(cls);
                return cls;
            }
        }
    }

    _objc_fatal("no class for metaclass %p", metacls);

    return cls;
}


Class _class_getNonMetaClass(Class cls_gen, id obj)
{
    class_t *cls = newcls(cls_gen);
    rwlock_write(&runtimeLock);
    cls = getNonMetaClass(cls, obj);
    assert(isRealized(cls));
    rwlock_unlock_write(&runtimeLock);
    
    return (Class)cls;
}


IMP prepareForMethodLookup(Class cls, SEL sel, BOOL init, id obj)
{
    rwlock_assert_unlocked(&runtimeLock);

    if (!isRealized(newcls(cls))) {
        rwlock_write(&runtimeLock);
        realizeClass(newcls(cls));
        rwlock_unlock_write(&runtimeLock);
    }

    if (init  &&  !_class_isInitialized(cls)) {
        _class_initialize (_class_getNonMetaClass(cls, obj));
        // If sel == initialize, _class_initialize will send +initialize and 
        // then the messenger will send +initialize again after this 
        // procedure finishes. Of course, if this is not being called 
        // from the messenger then it won't happen. 2778172
    }

    return NULL;
}


static BOOL noClassesRemapped(void)
{
    rwlock_assert_locked(&runtimeLock);

    BOOL result = (remappedClasses(NO) == NULL);
    return result;
}


static void remapClassRef(class_t **clsref)
{
    rwlock_assert_locked(&runtimeLock);

    class_t *newcls = remapClass(*clsref);    
    if (*clsref != newcls) *clsref = newcls;
}


static method_list_t *cat_method_list(const category_t *cat, BOOL isMeta)
{
    if (!cat) return NULL;

    if (isMeta) return cat->classMethods;
    else return cat->instanceMethods;
}


static size_t method_list_size(const method_list_t *mlist)
{
    return sizeof(method_list_t) + (mlist->count-1)*method_list_entsize(mlist);
}


static void setMethodListFixedUp(method_list_t *mlist)
{
    rwlock_assert_writing(&runtimeLock);
    assert(!isMethodListFixedUp(mlist));
    mlist->entsize_NEVER_USE = (mlist->entsize_NEVER_USE & ~3) | fixed_up_method_list;
}


static method_list_t *
fixupMethodList(method_list_t *mlist, bool bundleCopy, bool sort)
{
    assert(!isMethodListFixedUp(mlist));

    mlist = (method_list_t *)
        _memdup_internal(mlist, method_list_size(mlist));

    // fixme lock less in attachMethodLists ?
    sel_lock();

    // Unique selectors in list.
    uint32_t m;
    for (m = 0; m < mlist->count; m++) {
        method_t *meth = method_list_nth(mlist, m);
        SEL sel = sel_registerNameNoLock((const char *)meth->name, bundleCopy);
        meth->name = sel;

        if (ignoreSelector(sel)) {
            meth->imp = (IMP)&_objc_ignored_method;
        }
    }

    sel_unlock();

    // Sort by selector address.
    if (sort) {
        method_t::SortBySELAddress sorter;
        std::stable_sort(mlist->begin(), mlist->end(), sorter);
    }
    
    // Mark method list as uniqued and sorted
    setMethodListFixedUp(mlist);

    return mlist;
}


static void
attachMethodLists(class_t *cls, method_list_t **addedLists, int addedCount, 
                  BOOL baseMethods, BOOL methodsFromBundle, 
                  BOOL *inoutVtablesAffected)
{
    rwlock_assert_writing(&runtimeLock);

    // Don't scan redundantly
    bool scanForCustomRR = !UseGC && !cls->hasCustomRR();
    bool scanForCustomAWZ = !UseGC && !cls->hasCustomAWZ();

    // RR special cases:
    // NSObject's base instance methods are not custom RR.
    // All other root classes are custom RR.
    // updateCustomRR_AWZ also knows about these cases.
    if (baseMethods && scanForCustomRR  &&  cls->isRootClass()) {
        if (cls != classNSObject()) {
            cls->setHasCustomRR();
        }
        scanForCustomRR = false;
    }

    // AWZ special cases:
    // NSObject's base class methods are not custom AWZ.
    // All other root metaclasses are custom AWZ.
    // updateCustomRR_AWZ also knows about these cases.
    if (baseMethods && scanForCustomAWZ  &&  cls->isRootMetaclass()) {
        if (cls != classNSObject()->isa) {
            cls->setHasCustomAWZ();
        }
        scanForCustomAWZ = false;
    }

    // Method list array is NULL-terminated.
    // Some elements of lists are NULL; we must filter them out.

    method_list_t *oldBuf[2];
    method_list_t **oldLists;
    int oldCount = 0;
    if (cls->data()->flags & RW_METHOD_ARRAY) {
        oldLists = cls->data()->method_lists;
    } else {
        oldBuf[0] = cls->data()->method_list;
        oldBuf[1] = NULL;
        oldLists = oldBuf;
    }
    if (oldLists) {
        while (oldLists[oldCount]) oldCount++;
    }
        
    int newCount = oldCount;
    for (int i = 0; i < addedCount; i++) {
        if (addedLists[i]) newCount++;  // only non-NULL entries get added
    }

    method_list_t *newBuf[2];
    method_list_t **newLists;
    if (newCount > 1) {
        newLists = (method_list_t **)
            _malloc_internal((1 + newCount) * sizeof(*newLists));
    } else {
        newLists = newBuf;
    }

    // Add method lists to array.
    // Reallocate un-fixed method lists.
    // The new methods are PREPENDED to the method list array.

    newCount = 0;
    int i;
    for (i = 0; i < addedCount; i++) {
        method_list_t *mlist = addedLists[i];
        if (!mlist) continue;

        // Fixup selectors if necessary
        if (!isMethodListFixedUp(mlist)) {
            mlist = fixupMethodList(mlist, methodsFromBundle, true/*sort*/);
        }

#if SUPPORT_VTABLE
        // Scan for vtable updates
        if (inoutVtablesAffected  &&  !*inoutVtablesAffected) {
            uint32_t m;
            for (m = 0; m < mlist->count; m++) {
                SEL sel = method_list_nth(mlist, m)->name;
                if (vtable_containsSelector(sel)) {
                    *inoutVtablesAffected = YES;
                    break;
                }
            }
        }
#endif

        // Scan for method implementations tracked by the class's flags
        for (uint32_t m = 0; 
             (scanForCustomRR || scanForCustomAWZ)  &&  m < mlist->count; 
             m++) 
        {
            SEL sel = method_list_nth(mlist, m)->name;
            if (scanForCustomRR  &&  isRRSelector(sel)) {
                cls->setHasCustomRR();
                scanForCustomRR = false;
            } else if (scanForCustomAWZ  &&  isAWZSelector(sel)) {
                cls->setHasCustomAWZ();
                scanForCustomAWZ = false;
            } 
        }
        
        // Fill method list array
        newLists[newCount++] = mlist;
    }

    // Copy old methods to the method list array
    for (i = 0; i < oldCount; i++) {
        newLists[newCount++] = oldLists[i];
    }
    if (oldLists  &&  oldLists != oldBuf) free(oldLists);

    // NULL-terminate
    newLists[newCount] = NULL;

    if (newCount > 1) {
        assert(newLists != newBuf);
        cls->data()->method_lists = newLists;
        changeInfo(cls, RW_METHOD_ARRAY, 0);
    } else {
        assert(newLists == newBuf);
        cls->data()->method_list = newLists[0];
        assert(!(cls->data()->flags & RW_METHOD_ARRAY));
    }
}


static void
attachCategoryMethods(class_t *cls, category_list *cats, 
                      BOOL *inoutVtablesAffected)
{
    if (!cats) return;
#if SUPPORT_ENVIRON
    if (PrintReplacedMethods) printReplacements(cls, cats);
#endif

    BOOL isMeta = isMetaClass(cls);
    method_list_t **mlists = (method_list_t **)
        _malloc_internal(cats->count * sizeof(*mlists));

    // Count backwards through cats to get newest categories first
    int mcount = 0;
    int i = cats->count;
    BOOL fromBundle = NO;
    while (i--) {
        method_list_t *mlist = cat_method_list(cats->list[i].cat, isMeta);
        if (mlist) {
            mlists[mcount++] = mlist;
            fromBundle |= cats->list[i].fromBundle;
        }
    }

    attachMethodLists(cls, mlists, mcount, NO, fromBundle, inoutVtablesAffected);

    _free_internal(mlists);

}


static property_t *
property_list_nth(const property_list_t *plist, uint32_t i)
{
    return (property_t *)(i*plist->entsize + (char *)&plist->first);
}


static chained_property_list *
buildPropertyList(const property_list_t *plist, category_list *cats, BOOL isMeta)
{
    chained_property_list *newlist;
    uint32_t count = 0;
    uint32_t p, c;

    // Count properties in all lists.
    if (plist) count = plist->count;
    if (cats) {
        for (c = 0; c < cats->count; c++) {
            category_t *cat = cats->list[c].cat;
            /*
            if (isMeta  &&  cat->classProperties) {
                count += cat->classProperties->count;
            } 
            else*/
            if (!isMeta  &&  cat->instanceProperties) {
                count += cat->instanceProperties->count;
            }
        }
    }
    
    if (count == 0) return NULL;

    // Allocate new list. 
    newlist = (chained_property_list *)
        _malloc_internal(sizeof(*newlist) + count * sizeof(property_t));
    newlist->count = 0;
    newlist->next = NULL;

    // Copy properties; newest categories first, then ordinary properties
    if (cats) {
        c = cats->count;
        while (c--) {
            property_list_t *cplist;
            category_t *cat = cats->list[c].cat;
            /*
            if (isMeta) {
                cplist = cat->classProperties;
                } else */
            {
                cplist = cat->instanceProperties;
            }
            if (cplist) {
                for (p = 0; p < cplist->count; p++) {
                    newlist->list[newlist->count++] = 
                        *property_list_nth(cplist, p);
                }
            }
        }
    }
    if (plist) {
        for (p = 0; p < plist->count; p++) {
            newlist->list[newlist->count++] = *property_list_nth(plist, p);
        }
    }

    assert(newlist->count == count);

    return newlist;
}


static const protocol_list_t **
buildProtocolList(category_list *cats, const protocol_list_t *base, 
                  const protocol_list_t **protos)
{
    const protocol_list_t **p, **newp;
    const protocol_list_t **newprotos;
    unsigned int count = 0;
    unsigned int i;

    // count protocol list in base
    if (base) count++;

    // count protocol lists in cats
    if (cats) for (i = 0; i < cats->count; i++) {
        category_t *cat = cats->list[i].cat;
        if (cat->protocols) count++;
    }

    // no base or category protocols? return existing protocols unchanged
    if (count == 0) return protos;

    // count protocol lists in protos
    for (p = protos; p  &&  *p; p++) {
        count++;
    }

    if (count == 0) return NULL;
    
    newprotos = (const protocol_list_t **)
        _malloc_internal((count+1) * sizeof(protocol_list_t *));
    newp = newprotos;

    if (base) {
        *newp++ = base;
    }

    for (p = protos; p  &&  *p; p++) {
        *newp++ = *p;
    }
    
    if (cats) for (i = 0; i < cats->count; i++) {
        category_t *cat = cats->list[i].cat;
        if (cat->protocols) {
            *newp++ = cat->protocols;
        }
    }

    *newp = NULL;

    return newprotos;
}


static void remethodizeClass(class_t *cls)
{
    category_list *cats;
    BOOL isMeta;

    rwlock_assert_writing(&runtimeLock);

    isMeta = isMetaClass(cls);

    // Re-methodizing: check for more categories
    if ((cats = unattachedCategoriesForClass(cls))) {
        chained_property_list *newproperties;
        const protocol_list_t **newprotos;
        
        if (PrintConnecting) {
            _objc_inform("CLASS: attaching categories to class '%s' %s", 
                         getName(cls), isMeta ? "(meta)" : "");
        }
        
        // Update methods, properties, protocols
        
        BOOL vtableAffected = NO;
        attachCategoryMethods(cls, cats, &vtableAffected);
        
        newproperties = buildPropertyList(NULL, cats, isMeta);
        if (newproperties) {
            newproperties->next = cls->data()->properties;
            cls->data()->properties = newproperties;
        }
        
        newprotos = buildProtocolList(cats, NULL, cls->data()->protocols);
        if (cls->data()->protocols  &&  cls->data()->protocols != newprotos) {
            _free_internal(cls->data()->protocols);
        }
        cls->data()->protocols = newprotos;
        
        _free_internal(cats);

        // Update method caches and vtables
        flushCaches(cls);
#if SUPPORT_VTABLE
        if (vtableAffected) flushVtables(cls);
#endif
    }
}


static class_t *getClass(const char *name)
{
    rwlock_assert_locked(&runtimeLock);

#if SUPPORT_DEBUGGER_MODE
    // allocated in _read_images
    assert(gdb_objc_realized_classes);

    // Try runtime-allocated table
    class_t *result = (class_t *)NXMapGet(gdb_objc_realized_classes, name);
    if (result) return result;
#endif

    // Try table from dyld shared cache
    return getPreoptimizedClass(name);
}


static void addNamedClass(class_t *cls, const char *name)
{
    rwlock_assert_writing(&runtimeLock);
    class_t *old;
    if ((old = getClass(name))) {
        inform_duplicate(name, (Class)old, (Class)cls);
    } else {
#if SUPPORT_DEBUGGER_MODE
        NXMapInsert(gdb_objc_realized_classes, name, cls);
#endif
    }
    assert(!(cls->data()->flags & RO_META));

    // wrong: constructed classes are already realized when they get here
    // assert(!isRealized(cls));
}


static void remapProtocolRef(protocol_t **protoref)
{
    rwlock_assert_locked(&runtimeLock);

    protocol_t *newproto = remapProtocol((protocol_ref_t)*protoref);
    if (*protoref != newproto) *protoref = newproto;
}


static void addUnattachedCategoryForClass(category_t *cat, class_t *cls, 
                                          header_info *catHeader)
{
    rwlock_assert_writing(&runtimeLock);

    BOOL catFromBundle = (catHeader->mhdr->filetype == MH_BUNDLE) ? YES: NO;

    // DO NOT use cat->cls! cls may be cat->cls->isa instead
    NXMapTable *cats = unattachedCategories();
    category_list *list;

    list = (category_list *)NXMapGet(cats, cls);
    if (!list) {
        list = (category_list *)
            _calloc_internal(sizeof(*list) + sizeof(list->list[0]), 1);
    } else {
        list = (category_list *)
            _realloc_internal(list, sizeof(*list) + sizeof(list->list[0]) * (list->count + 1));
    }
    list->list[list->count++] = (category_pair_t){cat, catFromBundle};
    NXMapInsert(cats, cls, list);
}


static void realizeAllClassesInImage(header_info *hi)
{
    rwlock_assert_writing(&runtimeLock);

    size_t count, i;
    classref_t *classlist;

    if (hi->allClassesRealized) return;

    classlist = _getObjc2ClassList(hi, &count);

    for (i = 0; i < count; i++) {
        realizeClass(remapClass(classlist[i]));
    }

    hi->allClassesRealized = YES;
}


static void realizeAllClasses(void)
{
    rwlock_assert_writing(&runtimeLock);

    header_info *hi;
    for (hi = FirstHeader; hi; hi = hi->next) {
        realizeAllClassesInImage(hi);
    }
}


void _read_images(header_info **hList, uint32_t hCount)
{
    header_info *hi;
    uint32_t hIndex;
    size_t count;
    size_t i;
    class_t **resolvedFutureClasses = NULL;
    size_t resolvedFutureClassCount = 0;
    static unsigned int totalMethodLists;
    static unsigned int preoptimizedMethodLists;
    static unsigned int totalClasses;
    static unsigned int preoptimizedClasses;
    static BOOL doneOnce;

    rwlock_assert_writing(&runtimeLock);

#define EACH_HEADER \
    hIndex = 0;         \
    crashlog_header_name(NULL) && hIndex < hCount && (hi = hList[hIndex]) && crashlog_header_name(hi); \
    hIndex++

    if (!doneOnce) {
        doneOnce = YES;
#if SUPPORT_VTABLE
        initVtables();
#endif

        // Count classes. Size various table based on the total.
        size_t total = 0;
        size_t unoptimizedTotal = 0;
        for (EACH_HEADER) {
            if (_getObjc2ClassList(hi, &count)) {
                total += count;
                if (!hi->inSharedCache) unoptimizedTotal += count;
            }
        }
        
        if (PrintConnecting) {
            _objc_inform("CLASS: found %zu classes during launch", total);
        }

#if SUPPORT_DEBUGGER_MODE
        // namedClasses (NOT realizedClasses)
        // Preoptimized classes don't go in this table.
        // 4/3 is NXMapTable's load factor
        size_t namedClassesSize = 
            (isPreoptimized() ? unoptimizedTotal : total) * 4 / 3;
        gdb_objc_realized_classes =
            NXCreateMapTableFromZone(NXStrValueMapPrototype, namedClassesSize, 
                                     _objc_internal_zone());
#endif

        // realizedClasses and realizedMetaclasses - less than the full total
        realized_class_hash = 
            NXCreateHashTableFromZone(NXPtrPrototype, total / 8, NULL, 
                                      _objc_internal_zone());
        realized_metaclass_hash = 
            NXCreateHashTableFromZone(NXPtrPrototype, total / 8, NULL, 
                                      _objc_internal_zone());
    }


    // Discover classes. Fix up unresolved future classes. Mark bundle classes.
    NXMapTable *future_named_class_map = futureNamedClasses();

    for (EACH_HEADER) {
        bool headerIsBundle = (hi->mhdr->filetype == MH_BUNDLE);
        bool headerInSharedCache = hi->inSharedCache;

        classref_t *classlist = _getObjc2ClassList(hi, &count);
        for (i = 0; i < count; i++) {
            class_t *cls = (class_t *)classlist[i];
            const char *name = getName(cls);
            
            if (missingWeakSuperclass(cls)) {
                // No superclass (probably weak-linked). 
                // Disavow any knowledge of this subclass.
                if (PrintConnecting) {
                    _objc_inform("CLASS: IGNORING class '%s' with "
                                 "missing weak-linked superclass", name);
                }
                addRemappedClass(cls, NULL);
                cls->superclass = NULL;
                continue;
            }

            class_t *newCls = NULL;
            if (NXCountMapTable(future_named_class_map) > 0) {
                newCls = (class_t *)NXMapGet(future_named_class_map, name);
                removeFutureNamedClass(name);
            }
            
            if (newCls) {
                // Copy class_t to future class's struct.
                // Preserve future's rw data block.
                class_rw_t *rw = newCls->data();
                memcpy(newCls, cls, sizeof(class_t));
                rw->ro = (class_ro_t *)newCls->data();
                newCls->setData(rw);
                
                addRemappedClass(cls, newCls);
                cls = newCls;

                // Non-lazily realize the class below.
                resolvedFutureClasses = (class_t **)
                    _realloc_internal(resolvedFutureClasses, 
                                      (resolvedFutureClassCount+1) 
                                      * sizeof(class_t *));
                resolvedFutureClasses[resolvedFutureClassCount++] = newCls;
            }

            totalClasses++;
            if (headerInSharedCache  &&  isPreoptimized()) {
                // class list built in shared cache
                // fixme strict assert doesn't work because of duplicates
                // assert(cls == getClass(name));
                assert(getClass(name));
                preoptimizedClasses++;
            } else {
                addNamedClass(cls, name);
            }             

            // for future reference: shared cache never contains MH_BUNDLEs
            if (headerIsBundle) {
                cls->data()->flags |= RO_FROM_BUNDLE;
                cls->isa->data()->flags |= RO_FROM_BUNDLE;
            }

            if (PrintPreopt) {
                const method_list_t *mlist;
                if ((mlist = ((class_ro_t *)cls->data())->baseMethods)) {
                    totalMethodLists++;
                    if (isMethodListFixedUp(mlist)) preoptimizedMethodLists++;
                }
                if ((mlist = ((class_ro_t *)cls->isa->data())->baseMethods)) {
                    totalMethodLists++;
                    if (isMethodListFixedUp(mlist)) preoptimizedMethodLists++;
                }
            }
        }
    }

    if (PrintPreopt  &&  totalMethodLists) {
        _objc_inform("PREOPTIMIZATION: %u/%u (%.3g%%) method lists pre-sorted",
                     preoptimizedMethodLists, totalMethodLists, 
                     100.0*preoptimizedMethodLists/totalMethodLists);
    }
    if (PrintPreopt  &&  totalClasses) {
        _objc_inform("PREOPTIMIZATION: %u/%u (%.3g%%) classes pre-registered",
                     preoptimizedClasses, totalClasses, 
                     100.0*preoptimizedClasses/totalClasses);
    }

    // Fix up remapped classes
    // Class list and nonlazy class list remain unremapped.
    // Class refs and super refs are remapped for message dispatching.
    
    if (!noClassesRemapped()) {
        for (EACH_HEADER) {
            class_t **classrefs = _getObjc2ClassRefs(hi, &count);
            for (i = 0; i < count; i++) {
                remapClassRef(&classrefs[i]);
            }
            // fixme why doesn't test future1 catch the absence of this?
            classrefs = _getObjc2SuperRefs(hi, &count);
            for (i = 0; i < count; i++) {
                remapClassRef(&classrefs[i]);
            }
        }
    }


    // Fix up @selector references
    sel_lock();
    for (EACH_HEADER) {
        if (PrintPreopt) {
            if (sel_preoptimizationValid(hi)) {
                _objc_inform("PREOPTIMIZATION: honoring preoptimized selectors in %s", 
                             hi->fname);
            }
            else if (_objcHeaderOptimizedByDyld(hi)) {
                _objc_inform("PREOPTIMIZATION: IGNORING preoptimized selectors in %s", 
                             hi->fname);
            }
        }
        
        if (sel_preoptimizationValid(hi)) continue;

        SEL *sels = _getObjc2SelectorRefs(hi, &count);
        BOOL isBundle = hi->mhdr->filetype == MH_BUNDLE;
        for (i = 0; i < count; i++) {
            sels[i] = sel_registerNameNoLock((const char *)sels[i], isBundle);
        }
    }
    sel_unlock();

    // Discover protocols. Fix up protocol refs.
    NXMapTable *protocol_map = protocols();
    for (EACH_HEADER) {
        extern class_t OBJC_CLASS_$_Protocol;
        Class cls = (Class)&OBJC_CLASS_$_Protocol;
        assert(cls);
        protocol_t **protocols = _getObjc2ProtocolList(hi, &count);
        // fixme duplicate protocol from bundle
        for (i = 0; i < count; i++) {
            if (!NXMapGet(protocol_map, protocols[i]->name)) {
                protocols[i]->isa = cls;
                NXMapKeyCopyingInsert(protocol_map, 
                                      protocols[i]->name, protocols[i]);
                if (PrintProtocols) {
                    _objc_inform("PROTOCOLS: protocol at %p is %s",
                                 protocols[i], protocols[i]->name);
                }
            } else {
                if (PrintProtocols) {
                    _objc_inform("PROTOCOLS: protocol at %p is %s (duplicate)",
                                 protocols[i], protocols[i]->name);
                }
            }
        }
    }
    for (EACH_HEADER) {
        protocol_t **protocols;
        protocols = _getObjc2ProtocolRefs(hi, &count);
        for (i = 0; i < count; i++) {
            remapProtocolRef(&protocols[i]);
        }
    }

    // Realize non-lazy classes (for +load methods and static instances)
    for (EACH_HEADER) {
        classref_t *classlist = 
            _getObjc2NonlazyClassList(hi, &count);
        for (i = 0; i < count; i++) {
            realizeClass(remapClass(classlist[i]));
        }
    }    

    // Realize newly-resolved future classes, in case CF manipulates them
    if (resolvedFutureClasses) {
        for (i = 0; i < resolvedFutureClassCount; i++) {
            realizeClass(resolvedFutureClasses[i]);
        }
        _free_internal(resolvedFutureClasses);
    }    

    // Discover categories. 
    for (EACH_HEADER) {
        category_t **catlist = 
            _getObjc2CategoryList(hi, &count);
        for (i = 0; i < count; i++) {
            category_t *cat = catlist[i];
            class_t *cls = remapClass(cat->cls);

            if (!cls) {
                // Category's target class is missing (probably weak-linked).
                // Disavow any knowledge of this category.
                catlist[i] = NULL;
                if (PrintConnecting) {
                    _objc_inform("CLASS: IGNORING category \?\?\?(%s) %p with "
                                 "missing weak-linked target class", 
                                 cat->name, cat);
                }
                continue;
            }

            // Process this category. 
            // First, register the category with its target class. 
            // Then, rebuild the class's method lists (etc) if 
            // the class is realized. 
            BOOL classExists = NO;
            if (cat->instanceMethods ||  cat->protocols  
                ||  cat->instanceProperties) 
            {
                addUnattachedCategoryForClass(cat, cls, hi);
                if (isRealized(cls)) {
                    remethodizeClass(cls);
                    classExists = YES;
                }
                if (PrintConnecting) {
                    _objc_inform("CLASS: found category -%s(%s) %s", 
                                 getName(cls), cat->name, 
                                 classExists ? "on existing class" : "");
                }
            }

            if (cat->classMethods  ||  cat->protocols  
                /* ||  cat->classProperties */) 
            {
                addUnattachedCategoryForClass(cat, cls->isa, hi);
                if (isRealized(cls->isa)) {
                    remethodizeClass(cls->isa);
                }
                if (PrintConnecting) {
                    _objc_inform("CLASS: found category +%s(%s)", 
                                 getName(cls), cat->name);
                }
            }
        }
    }

    // Category discovery MUST BE LAST to avoid potential races 
    // when other threads call the new category code before 
    // this thread finishes its fixups.

    // +load handled by prepare_load_methods()

    if (DebugNonFragileIvars) {
        realizeAllClasses();
    }

#undef EACH_HEADER
}


const char*
map_images_nolock(enum dyld_image_states state, uint32_t infoCount,
                  const struct dyld_image_info infoList[])
{
    static BOOL firstTime = YES;
    static BOOL wantsGC = NO;
    // static BOOL wantsCompaction = NO;
    uint32_t i;
    header_info *hi;
    header_info *hList[infoCount];
    uint32_t hCount;
    size_t selrefCount = 0;

    // Perform first-time initialization if necessary.
    // This function is called before ordinary library initializers. 
    // fixme defer initialization until an objc-using image is found?
    if (firstTime) {
        preopt_init();
    }

    if (PrintImages) {
        _objc_inform("IMAGES: processing %u newly-mapped images...\n", infoCount);
    }


    // Find all images with Objective-C metadata.
    hCount = 0;
    i = infoCount;
    while (i--) {
        const headerType *mhdr = (headerType *)infoList[i].imageLoadAddress;

        hi = addHeader(mhdr);
        if (!hi) {
            // no objc data in this entry
            continue;
        }
        if (mhdr->filetype == MH_EXECUTE) {
#if __OBJC2__
            size_t count;
            _getObjc2SelectorRefs(hi, &count);
            selrefCount += count;
            _getObjc2MessageRefs(hi, &count);
            selrefCount += count;
#else
            _getObjcSelectorRefs(hi, &selrefCount);
#endif
        }

        hList[hCount++] = hi;
        

        if (PrintImages) {
            _objc_inform("IMAGES: loading image for %s%s%s%s%s\n", 
                         hi->fname, 
                         mhdr->filetype == MH_BUNDLE ? " (bundle)" : "", 
                         _objcHeaderIsReplacement(hi) ? " (replacement)" : "",
                         _objcHeaderOptimizedByDyld(hi)?" (preoptimized)" : "",
                         _gcForHInfo2(hi));
        }
    }

    // Perform one-time runtime initialization that must be deferred until 
    // the executable itself is found. This needs to be done before 
    // further initialization.
    // (The executable may not be present in this infoList if the 
    // executable does not contain Objective-C code but Objective-C 
    // is dynamically loaded later. In that case, check_wants_gc() 
    // will do the right thing.)
    if (firstTime) {
        extern SEL FwdSel;  // in objc-msg-*.s
        sel_init(wantsGC, selrefCount);
        FwdSel = sel_registerName("forward::");

        arr_init();
    }

    _read_images(hList, hCount);

    firstTime = NO;

    return NULL;
}


const char *
map_images(enum dyld_image_states state, uint32_t infoCount,
           const struct dyld_image_info infoList[])
{
    const char *err;

    rwlock_write(&runtimeLock);
    err = map_images_nolock(state, infoCount, infoList);
    rwlock_unlock_write(&runtimeLock);
    return err;
}



IMP _class_lookupMethodAndLoadCache3(id obj, SEL sel, Class cls)
{        
    return lookUpMethod(cls, sel, YES/*initialize*/, NO/*cache*/, obj);
}


static uint32_t
unalignedInstanceSize(class_t *cls)
{
    assert(cls);
    assert(isRealized(cls));
    return (uint32_t)cls->data()->ro->instanceSize;
}


static uint32_t
alignedInstanceSize(class_t *cls)
{
    assert(cls);
    assert(isRealized(cls));
    return (uint32_t)((unalignedInstanceSize(cls) + WORD_MASK) & ~WORD_MASK);
}


static id 
_objc_constructInstance(Class cls, void *bytes) 
{
    id obj = (id)bytes;

    // Set the isa pointer
    obj->isa = cls;  // need not be object_setClass

    // Call C++ constructors, if any.
    if (!object_cxxConstruct(obj)) {
        // Some C++ constructor threw an exception. 
        return nil;
    }

    return obj;
}


static IMP lookupMethodInClassAndLoadCache(Class cls, SEL sel)
{
    Method meth;
    IMP imp;

    // fixme this still has the method list vs method cache race 
    // because it doesn't hold a lock across lookup+cache_fill, 
    // but it's only used for .cxx_construct/destruct and we assume 
    // categories don't change them.

    // Search cache first.
    imp = _cache_getImp(cls, sel);
    if (imp) return imp;

    // Cache miss. Search method list.

    meth = _class_getMethodNoSuper(cls, sel);

    if (meth) {
        // Hit in method list. Cache it.
        _cache_fill(cls, meth, sel);
        return method_getImplementation(meth);
    } else {
        // Miss in method list. Cache objc_msgForward.
        _cache_addForwardEntry(cls, sel);
        return _objc_msgForward_internal;
    }
}


static void object_cxxDestructFromClass(id obj, Class cls)
{
    void (*dtor)(id);

    // Call cls's dtor first, then superclasses's dtors.

    for ( ; cls != NULL; cls = _class_getSuperclass(cls)) {
        if (!_class_hasCxxStructors(cls)) return; 
        dtor = (void(*)(id))
            lookupMethodInClassAndLoadCache(cls, SEL_cxx_destruct);
        if (dtor != (void(*)(id))_objc_msgForward_internal) {
            if (PrintCxxCtors) {
                _objc_inform("CXX: calling C++ destructors for class %s", 
                             _class_getName(cls));
            }
            (*dtor)(obj);
        }
    }
}


static BOOL object_cxxConstructFromClass(id obj, Class cls)
{
    id (*ctor)(id);
    Class supercls;

    // Stop if neither this class nor any superclass has ctors.
    if (!_class_hasCxxStructors(cls)) return YES;  // no ctor - ok

    supercls = _class_getSuperclass(cls);

    // Call superclasses' ctors first, if any.
    if (supercls) {
        BOOL ok = object_cxxConstructFromClass(obj, supercls);
        if (!ok) return NO;  // some superclass's ctor failed - give up
    }

    // Find this class's ctor, if any.
    ctor = (id(*)(id))lookupMethodInClassAndLoadCache(cls, SEL_cxx_construct);
    if (ctor == (id(*)(id))_objc_msgForward_internal) return YES;  // no ctor - ok
    
    // Call this class's ctor.
    if (PrintCxxCtors) {
        _objc_inform("CXX: calling C++ constructors for class %s", _class_getName(cls));
    }
    if ((*ctor)(obj)) return YES;  // ctor called and succeeded - ok

    // This class's ctor was called and failed. 
    // Call superclasses's dtors to clean up.
    if (supercls) object_cxxDestructFromClass(obj, supercls);
    return NO;
}


Class object_getClass(id obj)
{
    return _object_getClass(obj);
}


const char *object_getClassName(id obj)
{
    Class isa = _object_getClass(obj);
    if (isa) return _class_getName(isa);
    else return "nil";
}


BOOL object_cxxConstruct(id obj)
{
    if (!obj) return YES;
    if (OBJC_IS_TAGGED_PTR(obj)) return YES;
    return object_cxxConstructFromClass(obj, obj->isa);  // need not be object_getClass
}


void object_cxxDestruct(id obj)
{
    if (!obj) return;
    if (OBJC_IS_TAGGED_PTR(obj)) return;
    object_cxxDestructFromClass(obj, obj->isa);  // need not be object_getClass
}


void
_class_setInstancesHaveAssociatedObjects(Class cls_gen)
{
    class_t *cls = newcls(cls_gen);
    assert(isFuture(cls)  ||  isRealized(cls));
    changeInfo(cls, RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS, 0);
}


id
_objc_constructOrFree(Class cls, void *bytes)
{
    id obj = _objc_constructInstance(cls, bytes);
    if (!obj) {
        free(bytes);
    }

    return obj;
}


static BOOL
hasCxxStructors(class_t *cls)
{
    // this DOES check superclasses too, because addSubclass()
    // propagates the flag from the superclass.
    assert(isRealized(cls));
    return (cls->data()->flags & RW_HAS_CXX_STRUCTORS) ? YES : NO;
}


BOOL
_class_instancesHaveAssociatedObjects(Class cls_gen)
{
    class_t *cls = newcls(cls_gen);
    assert(isFuture(cls)  ||  isRealized(cls));
    return (cls->data()->flags & RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS) ? YES : NO;
}


BOOL
_class_hasCxxStructors(Class cls)
{
    return hasCxxStructors(newcls(cls));
}


void *objc_destructInstance(id obj)
{
    if (obj) {
        Class isa_gen = _object_getClass(obj);
        class_t *isa = newcls(isa_gen);

        // Read all of the flags at once for performance.
        bool cxx = hasCxxStructors(isa);
        bool assoc = !UseGC && _class_instancesHaveAssociatedObjects(isa_gen);

        // This order is important.
        if (cxx) object_cxxDestruct(obj);
        if (assoc) _object_remove_assocations(obj);
        
        if (!UseGC) objc_clear_deallocating(obj);
    }

    return obj;
}


id
object_dispose(id obj)
{
    if (!obj) return nil;

    objc_destructInstance(obj);
    
    free(obj);

    return nil;
}


id
look_up_class(const char *name, 
              BOOL includeUnconnected __attribute__((unused)), 
              BOOL includeClassHandler __attribute__((unused)))
{
    if (!name) return nil;

    rwlock_read(&runtimeLock);
    class_t *result = getClass(name);
    BOOL unrealized = result  &&  !isRealized(result);
    rwlock_unlock_read(&runtimeLock);
    if (unrealized) {
        rwlock_write(&runtimeLock);
        realizeClass(result);
        rwlock_unlock_write(&runtimeLock);
    }
    return (id)result;
}


Method
_class_getMethodNoSuper(Class cls, SEL sel)
{
    rwlock_read(&runtimeLock);
    Method result = (Method)getMethodNoSuper_nolock(newcls(cls), sel);
    rwlock_unlock_read(&runtimeLock);
    return result;
}


id objc_getClass(const char *aClassName)
{
    if (!aClassName) return Nil;

    // NO unconnected, YES class handler
    return look_up_class(aClassName, NO, YES);
}


id
class_createInstance(Class cls, size_t extraBytes)
{
    if (!cls) return nil;

    assert(isRealized(newcls(cls)));

    size_t size = alignedInstanceSize(newcls(cls)) + extraBytes;

    // CF requires all object be at least 16 bytes.
    if (size < 16) size = 16;

    id obj = (id)calloc(1, size);
    if (!obj)
		return nil;

    obj->isa = cls;  // need not be object_setClass
    if (_class_hasCxxStructors(cls)) {
        obj = _objc_constructOrFree(cls, obj);
    }
    return obj;
}


void class_t::setHasCustomRR(bool inherited) 
{
    rwlock_assert_writing(&runtimeLock);

    if (hasCustomRR()) return;
    
    FOREACH_REALIZED_CLASS_AND_SUBCLASS(c, this, {
        if (PrintCustomRR && !c->hasCustomRR()) {
            _objc_inform("CUSTOM RR:  %s%s%s", getName(c), 
                         isMetaClass(c) ? " (meta)" : "", 
                         (inherited  ||  c != this) ? " (inherited)" : "");
        }
#if CLASS_FAST_FLAGS_VIA_RW_DATA        
        c->data_NEVER_USE |= (uintptr_t)1;
#else
        c->data()->flags |= RW_HAS_CUSTOM_RR;
#endif
    });
}


void class_t::setHasCustomAWZ(bool inherited ) 
{
    rwlock_assert_writing(&runtimeLock);

    if (hasCustomAWZ()) return;
    
    FOREACH_REALIZED_CLASS_AND_SUBCLASS(c, this, {
        if (PrintCustomAWZ && !c->hasCustomAWZ()) {
            _objc_inform("CUSTOM AWZ: %s%s%s", getName(c), 
                         isMetaClass(c) ? " (meta)" : "", 
                         (inherited  ||  c != this) ? " (inherited)" : "");
        }
#if CLASS_FAST_FLAGS_VIA_RW_DATA        
        c->data_NEVER_USE |= (uintptr_t)2;
#else
        c->data()->flags |= RW_HAS_CUSTOM_AWZ;
#endif
    });
}


void _objc_init(void)
{
    static bool initialized = false;
    if (initialized) return;
    initialized = true;
    
    // environ_init();
    tls_init();
    lock_init();
    exception_init();

    // Register for unmap first, in case some +load unmaps something
    _dyld_register_func_for_remove_image(&unmap_image);
    dyld_register_image_state_change_handler(dyld_image_state_bound, 1/*batch*/, &map_images);
    dyld_register_image_state_change_handler(dyld_image_state_dependents_initialized, 0/*not batch*/, &load_images);
}


/*
static class _objc_static_init
{
	_objc_static_init()
	{
		_objc_init();
	}
} objc_static_init;
*/


#endif


// ------------------------------------------------------------------------- //

/*
@interface MyObject : NSObject
@end


@implementation MyObject

+ (void)load
{
	printf("MyObject: load\n");
}

- (void)dealloc
{
	printf("MyObject: dealloc\n");
}

@end
*/


int main()
{
	_objc_init();
	printf("EHLO\n");

/*
	id o = class_createInstance((Class)classNSObject(), 0);
	assert(o);
	object_dispose(o);
	o = nil;
*/
	NSObject* o = [[NSObject alloc] init];
	o = nil;

	printf("GDBY\n");
	return 0;
}

