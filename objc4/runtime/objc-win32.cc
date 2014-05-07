
#include "objc-config.h"

#if TARGET_OS_WIN32

#include <stdio.h>
#include <stdlib.h>

#define WIN32_LEAN_AND_MEAN
#define _NO_BOOL_TYPEDEF
#define BOOL WINBOOL
#include <windows.h>
#undef BOOL

#include "objc-private.h"
#include "objc-os.h"
#include "objc-runtime-new.h"


/*
WINBOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
		// _objc_init();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
*/


static struct _objc_initializer_
{
	_objc_initializer_()
	{
		_objc_init();
	}
} _objc_initializer_var;



// The assert below ensures that the assumptions in objc-sections-win32.s
// are correct. (There is probably a better way of doing all the cross-checks.)
// The other assert check sanity of our section merging: there should be one
// empty element in the beginning, which is declared in objc-sections-win32.s

#define GETSECT(_name, _type, _sectname, _size) \
	extern _type _sectname ## _A; extern _type _sectname ## _Z; \
	OBJC_EXPORT _type* _name(const header_info *hi, size_t *outCount) { \
		assert(sizeof(_type) == _size * sizeof(void*)); \
		_type* data = & _sectname ## _A; \
		*outCount = (& _sectname ## _Z - data); \
		assert((int)(*outCount) >= 1); \
		(*outCount)--; \
		data++; \
		DLOG("*** %s: %u", #_sectname, *outCount); \
		return data; }

#define GETSECT0(_name, _type, _sectname, _size) \
	OBJC_EXPORT _type* _name(const header_info *hi, size_t *outCount) { \
		*outCount = 0; \
		return NULL; }


GETSECT(_getObjc2ClassList,           classref_t,       __objc_classlist, 1);
GETSECT(_getObjc2SelectorRefs,        SEL,              __objc_selrefs, 1)
GETSECT(_getObjc2MessageRefs,         message_ref_t,    __objc_msgrefs, 2);
GETSECT(_getObjc2ClassRefs,           class_t *,        __objc_classrefs, 1);
GETSECT(_getObjc2SuperRefs,           class_t *,        __objc_superrefs, 1);
GETSECT(_getObjc2NonlazyClassList,    classref_t,       __objc_nlclslist, 1);
GETSECT(_getObjc2CategoryList,        category_t *,     __objc_catlist, 1);
GETSECT(_getObjc2NonlazyCategoryList, category_t *,     __objc_nlcatlist, 1);
GETSECT(_getObjc2ProtocolList,        protocol_t *,     __objc_protolist, 1);
GETSECT(_getObjc2ProtocolRefs,        protocol_t *,     __objc_protorefs, 1);



static header_info *__hinfo = NULL;  // cookie from runtime
extern IMAGE_DOS_HEADER __ImageBase;  // this image's header


OBJC_EXPORT void _objc_load_image(HMODULE image, header_info *hinfo)
{
    prepare_load_methods(hinfo);
    call_load_methods();
}


OBJC_EXPORT header_info *_objc_init_image(HMODULE image)
{
	static const objc_image_info image_info = {0, 0};

    header_info *hi = (header_info *)_malloc_internal(sizeof(header_info));
    size_t count, i;

    hi->mhdr = (const headerType *)image;
    hi->info = &image_info;
    hi->allClassesRealized = NO;
    hi->moduleName = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
    GetModuleFileName((HMODULE)(hi->mhdr), hi->moduleName, MAX_PATH * sizeof(TCHAR));

    appendHeader(hi);

    static bool firstTime = true;
	if (firstTime)
	{
		size_t selrefCount = 0;
		_getObjc2SelectorRefs(hi, &selrefCount);
		sel_init(SUPPORT_GC, selrefCount);
		arr_init();
		firstTime = false;
	}

    _read_images(&hi, 1);

    return hi;
}


OBJC_EXPORT void _objc_init(void)
{
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    __hinfo = _objc_init_image((HMODULE)&__ImageBase);
	environ_init();
	tls_init();
	lock_init();
	exception_init();
    _objc_load_image((HMODULE)&__ImageBase, __hinfo);
}


#endif
