#include <stdio.h>

#include "Foundation/NSObject.h"


/*
@interface MyObject : NSObject
@end


@implementation MyObject
@end
*/

int main()
{
	printf("EHLO\n");
	NSObject* o = [[NSObject alloc] init];
	o = nil;
	return 0;
}
