#include <stdio.h>

#include "Foundation/NSObject.h"


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


int main()
{
	printf("EHLO\n");
	NSObject* o = [[MyObject alloc] init];
	o = nil;
	printf("GDBY\n");
	return 0;
}
