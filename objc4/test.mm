
#include <stdio.h>
#include <assert.h>

/*
#include <malloc/malloc.h>
#include "objc-private.h"
#include "objc-os.h"
#include "objc-runtime-new.h"
#include "objc/runtime.h"
*/

#include "Foundation/NSObject.h"


@interface MyObject : NSObject
@end


@implementation MyObject

+ (void)load
{
	printf("MyObject: load\n");
}

- (void)hello:(NSInteger)arg
{
	printf("MyObject: hello %d\n", arg);
}

- (NSUInteger)hash
{
	NSUInteger shash = super.hash;
	printf("super.hash=%u\n", shash);
	return shash;
}

- (void)dealloc
{
	printf("MyObject: dealloc\n");
}

@end


int main()
{
	printf("EHLO\n");

	MyObject* obj = [[MyObject alloc] init];
	[obj hello:1];
	[obj hello:2];

	printf("NSObject=%p  MyObject=%p\n", NSObject.class, MyObject.class);
	printf("@hash=%p\n", @selector(hash));
	printf("obj=%p\n", obj);

	NSUInteger hash = obj.hash;
	printf("obj.hash=%u\n", hash);
	NSUInteger hash2 = [obj hash];
	assert(hash2 == hash);

	obj = nil;

/*
	Class cls = objc_getClass("NSObject");
	id obj = class_createInstance((id)cls, 0);
	printf("class=%p object=%p\n", cls, obj);
	assert(object_getClass(obj) == (Class)cls);
	assert(strcmp(object_getClassName(obj), "NSObject") == 0);
	Method meth = class_getClassMethod(cls, @selector(class));
	printf("method class=%p\n", meth);
*/

	printf("GDBY\n");
	return 0;
}
