Subjective: Windows Port of the Objective-C 2.0 Runtime
============================================================================


----------------------------------------------------------------------------

###This is a work in progress. Please be *impatient*, contribute!

----------------------------------------------------------------------------


*Subjective* is an attempt to bring Objective C 2.0 with ARC support to 
Windows.

This project is a fork of objc4-532.2, the Objective C runtime that ships 
with OS X 10.8.5. The port can be compiled using llvm-clang on OS X combined 
with the MinGW linker.

There are certain limitations many of which are a matter of extra work, while
others, such as exceptions and blocks, depend on more serious work in 3rd 
party projects. The limitations are:

• 32-bit only - 64-bit is underway

• Static linking only - dynamic linking is underway

• No closures/blocks - until libdispatch supports them on Windows

• No exceptions - until clang supports them on Windows

• No old style GC - until someone cares...

• Internals: no vtables, no gdb support, just plain malloc, no preoptimizations - some of these things will be available under the 64-bit
build.


----------------------------------------------------------------------------

###Prerequisites (OS X):

• MinGW cross-compile environment for OS X installed at /usr/local; currently
only the i686-w64-mingw32 package is required:
http://mingw-w64.sourceforge.net/download.php

• Xcode 5.1+


----------------------------------------------------------------------------

###Building

At the moment we don't have a procedure that would build a production-ready Win32 library. There is an Xcode project with some self-descriptive schemes 
and also a Makefile that produces `test.exe`.

