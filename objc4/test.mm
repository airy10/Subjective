
#include <stdio.h>
#include <assert.h>

#include "Foundation/NSObject.h" // for NSObject interface


@interface MyObject : NSObject
@end


@implementation MyObject

+ (void)load
{
	printf("MyObject: load\n");
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
	printf("obj.hash=%u\n", (unsigned)hash);
	NSUInteger hash2 = [obj hash];
	assert(hash2 == hash);

	obj = nil;

	printf("GDBY\n");
	return 0;
}
