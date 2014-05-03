
#include "objc-config.h"

#if TARGET_OS_WIN32

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

#include "objc-win32.h"


WINBOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        environ_init();
        tls_init();
        lock_init();
        sel_init(NO, 3500);  // old selector heuristic
        exception_init();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


OBJC_EXPORT void *_objc_init_image(HMODULE image, const objc_sections *sects)
{
    header_info *hi = _malloc_internal(sizeof(header_info));
    size_t count, i;

    hi->mhdr = (const headerType *)image;
    hi->info = sects->iiStart;
    hi->allClassesRealized = NO;
    hi->modules = sects->modStart ? (Module *)((void **)sects->modStart+1) : 0;
    hi->moduleCount = (Module *)sects->modEnd - hi->modules;
    hi->protocols = sects->protoStart ? (struct old_protocol **)((void **)sects->protoStart+1) : 0;
    hi->protocolCount = (struct old_protocol **)sects->protoEnd - hi->protocols;
    hi->imageinfo = NULL;
    hi->imageinfoBytes = 0;
    // hi->imageinfo = sects->iiStart ? (uint8_t *)((void **)sects->iiStart+1) : 0;;
//     hi->imageinfoBytes = (uint8_t *)sects->iiEnd - hi->imageinfo;
    hi->selrefs = sects->selrefsStart ? (SEL *)((void **)sects->selrefsStart+1) : 0;
    hi->selrefCount = (SEL *)sects->selrefsEnd - hi->selrefs;
    hi->clsrefs = sects->clsrefsStart ? (Class *)((void **)sects->clsrefsStart+1) : 0;
    hi->clsrefCount = (Class *)sects->clsrefsEnd - hi->clsrefs;

    count = 0;
    for (i = 0; i < hi->moduleCount; i++) {
        if (hi->modules[i]) count++;
    }
    hi->mod_count = 0;
    hi->mod_ptr = 0;
    if (count > 0) {
        hi->mod_ptr = malloc(count * sizeof(struct objc_module));
        for (i = 0; i < hi->moduleCount; i++) {
            if (hi->modules[i]) memcpy(&hi->mod_ptr[hi->mod_count++], hi->modules[i], sizeof(struct objc_module));
        }
    }
    
    hi->moduleName = malloc(MAX_PATH * sizeof(TCHAR));
    GetModuleFileName((HMODULE)(hi->mhdr), hi->moduleName, MAX_PATH * sizeof(TCHAR));

    appendHeader(hi);

    if (PrintImages) {
        _objc_inform("IMAGES: loading image for %s%s%s\n", 
            hi->fname, 
            headerIsBundle(hi) ? " (bundle)" : "", 
            _objcHeaderIsReplacement(hi) ? " (replacement)":"");
    }

    _read_images(&hi, 1);

    return hi;
}

OBJC_EXPORT void _objc_load_image(HMODULE image, header_info *hinfo)
{
    prepare_load_methods(hinfo);
    call_load_methods();
}

OBJC_EXPORT void _objc_unload_image(HMODULE image, header_info *hinfo)
{
    _objc_fatal("image unload not supported");
}



// Boundary symbols for metadata sections

#pragma section(".objc_module_info$A",long,read,write)
#pragma data_seg(".objc_module_info$A")
static uintptr_t __objc_modStart = 0;
#pragma section(".objc_module_info$C",long,read,write)
#pragma data_seg(".objc_module_info$C")
static uintptr_t __objc_modEnd = 0;

#pragma section(".objc_protocol$A",long,read,write)
#pragma data_seg(".objc_protocol$A")
static uintptr_t __objc_protoStart = 0;
#pragma section(".objc_protocol$C",long,read,write)
#pragma data_seg(".objc_protocol$C")
static uintptr_t __objc_protoEnd = 0;

#pragma section(".objc_image_info$A",long,read,write)
#pragma data_seg(".objc_image_info$A")
static uintptr_t __objc_iiStart = 0;
#pragma section(".objc_image_info$C",long,read,write)
#pragma data_seg(".objc_image_info$C")
static uintptr_t __objc_iiEnd = 0;

#pragma section(".objc_message_refs$A",long,read,write)
#pragma data_seg(".objc_message_refs$A")
static uintptr_t __objc_selrefsStart = 0;
#pragma section(".objc_message_refs$C",long,read,write)
#pragma data_seg(".objc_message_refs$C")
static uintptr_t __objc_selrefsEnd = 0;

#pragma section(".objc_class_refs$A",long,read,write)
#pragma data_seg(".objc_class_refs$A")
static uintptr_t __objc_clsrefsStart = 0;
#pragma section(".objc_class_refs$C",long,read,write)
#pragma data_seg(".objc_class_refs$C")
static uintptr_t __objc_clsrefsEnd = 0;

#pragma data_seg()

// Merge all metadata into .data
// fixme order these by usage?
#pragma comment(linker, "/MERGE:.objc_module_info=.data")
#pragma comment(linker, "/MERGE:.objc_protocol=.data")
#pragma comment(linker, "/MERGE:.objc_image_info=.data")
#pragma comment(linker, "/MERGE:.objc_message_refs=.data")
#pragma comment(linker, "/MERGE:.objc_class_refs=.data")


// Image initializers

static void *__hinfo = NULL;  // cookie from runtime
extern IMAGE_DOS_HEADER __ImageBase;  // this image's header

static int __objc_init(void)
{
    objc_sections sections = {
        5, 
        &__objc_modStart, &__objc_modEnd, 
        &__objc_protoStart, &__objc_protoEnd, 
        &__objc_iiStart, &__objc_iiEnd, 
        &__objc_selrefsStart, &__objc_selrefsEnd, 
        &__objc_clsrefsStart, &__objc_clsrefsEnd, 
    };
    __hinfo = _objc_init_image((HMODULE)&__ImageBase, &sections);
    return 0;
}

static void __objc_unload(void)
{
    _objc_unload_image((HMODULE)&__ImageBase, __hinfo);
}

static int __objc_load(void)
{
    _objc_load_image((HMODULE)&__ImageBase, __hinfo);
    return 0;
}

// run _objc_init_image ASAP
#pragma section(".CRT$XIAA",long,read,write)
#pragma data_seg(".CRT$XIAA")
static void *__objc_init_fn = &__objc_init;

// run _objc_load_image (+load methods) after all other initializers; 
// otherwise constant NSStrings are not initialized yet
#pragma section(".CRT$XCUO",long,read,write)
#pragma data_seg(".CRT$XCUO")
static void *__objc_load_fn = &__objc_load;

// _objc_unload_image is called by atexit(), not by an image terminator

#pragma data_seg()

#endif
