
/*
 * Section definitions for grouping the internal RT data
 * WIN32 build only
 *
 * The idea is that we mark start and end for each of ObjC's internal sections
 * so that the runtime can load and interpret them during initialization.
 * There is also a ld script `objc-win32.ld` that re-orders this data and
 * labels properly.
 *
 * The reason we define these in an asm file is that it's not easy to find
 * a C compiler that: (a) cross-compiles for WIN32 on OSX, (b) consistently
 * understands section-related pragmas or attributes and (c) is in stable
 * release. As of 2014-06-06 clang's pragmas are still experimental, and gcc
 * chooses to ignore my __attribute__((section())).
 *
 * Why I'm saying all this is, ideally this should be moved to objc-win32.cc.
 * Or maybe some radical solution is needed specifically for ObjC on Windows,
 * because this section juggling is too fragile.
 *
 * -- H.M.
 */

#include <TargetConditionals.h>
#include "objc-config.h"

#if SUBJECTIVE_WIN32

.macro OBJC_SECT name size

.data

.section __objc_\name\()$A
.align 4
.global ___objc_\name\()_A
___objc_\name\()_A:
	.long 0
.if \size == 2
	.long 0
.endif

.section __objc_\name\()$Z
.align 4
.global ___objc_\name\()_Z
___objc_\name\()_Z:
	.long 0
.if \size == 2
	.long 0
.endif

.endm


OBJC_SECT classlist 1
OBJC_SECT selrefs 1
OBJC_SECT msgrefs 2
OBJC_SECT classrefs 1
OBJC_SECT superrefs 1
OBJC_SECT nlclslist 1
OBJC_SECT catlist 1
OBJC_SECT nlcatlist 1
OBJC_SECT protolist 1
OBJC_SECT protorefs 1

#endif
