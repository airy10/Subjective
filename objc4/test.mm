
#include <stdio.h>

#include <malloc/malloc.h>
#include "objc-private.h"
#include "objc-os.h"
#include "objc-runtime-new.h"
#include "objc/runtime.h"

// #include "Foundation/NSObject.h"

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
	printf("EHLO\n");

	Class cls = objc_getClass("NSObject");
	id obj = class_createInstance((id)cls, 0);
	printf("class=%p object=%p\n", cls, obj);
	assert(object_getClass(obj) == (Class)cls);
	assert(strcmp(object_getClassName(obj), "NSObject") == 0);
	Method meth = class_getClassMethod(cls, @selector(class));
	printf("method class=%p\n", meth);

	printf("GDBY\n");
	return 0;
}
