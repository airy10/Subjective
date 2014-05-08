
#include <stdio.h>
#include <assert.h>

#include "Foundation/NSObject.h" // for NSObject interface


@interface MyObject : NSObject
@end


@implementation MyObject

static int allocCount = 0;

+ (void)load
{
	printf("MyObject: load\n");
}

- (id)init
{
	allocCount++;
	return [super init];
}

- (void)hello:(NSInteger)arg
{
	printf("MyObject: hello %d\n", (int)arg);
}

- (NSUInteger)hash
{
	NSUInteger shash = super.hash;
	printf("super.hash=%u\n", (unsigned)shash);
	return shash;
}

- (void)throwCpp
{
	throw 1;
}

- (void)throwObjC
{
	@throw [[NSObject alloc] init];
}

- (void)dealloc
{
	printf("MyObject: dealloc\n");
	allocCount--;
}

@end


int main()
{
	printf("EHLO\n");

	MyObject* obj = [[MyObject alloc] init];
	assert(allocCount == 1);
	[obj hello:1];
	[obj hello:2];

	printf("NSObject=%p  MyObject=%p\n", NSObject.class, MyObject.class);
	printf("@hash=%p\n", @selector(hash));
	printf("obj=%p\n", obj);

	NSUInteger hash = obj.hash;
	printf("obj.hash=%u\n", (unsigned)hash);
	NSUInteger hash2 = [obj hash];
	assert(hash2 == hash);
/*
	bool cppCaught = false;
	try
	{
		[obj throwCpp];
	}
	catch (int e)
	{
		cppCaught = true;
		printf("Caught %d\n", e);
	}
	assert(cppCaught);

	bool objcCaught = false;
	@try
	{
		[obj throwObjC];
	}
	@catch (NSObject* e)
	{
		objcCaught = true;
		printf("Caught %p\n", e);
	}
	assert(objcCaught);
*/
	obj = nil;
	assert(allocCount == 0);

	printf("GDBY\n");
	return 0;
}
