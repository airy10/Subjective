
TRIPLE = i686-pc-win32
MINGW = i686-w64-mingw32

# The following is for the <*intrin.h>
CLANG_TOOLCHAIN_DIR=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/5.1

BUILD_DIR = build

BUILD_OBJ_DIR = $(BUILD_DIR)/$(TRIPLE)/objects

TARGET = -target $(TRIPLE)

INCLUDE = -Iinclude -I../include -I../include/objc \
	-isystem /usr/local/$(MINGW)/include \
	-isystem /usr/local/lib/gcc/$(MINGW)/4.9.0/include \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/ \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/$(MINGW)

DEFINES = -DDEBUG -DBUILDING_OBJC \
	-D__OBJC2__=1 -DSUBJECTIVE=1 -DSUBJECTIVE_WIN32=1 \
	-DWIN32 -DTARGET_OS_WIN32=1 -DTARGET_CPU_X86=1 -D_X86_

CC_OBJCRT = -fobjc-runtime=macosx \
	-isystem $(CLANG_TOOLCHAIN_DIR)/include \
	-Wno-deprecated-objc-pointer-introspection \
	-Wno-deprecated-objc-isa-usage -Wno-inline-new-delete \
	-Wno-cast-of-sel-type -Wno-objc-root-class \
	-Wno-duplicate-decl-specifier -Wno-c++11-extensions \
	-Wunknown-pragmas -Werror

CC = /usr/bin/clang $(TARGET)
MINGW_CC = /usr/local/bin/$(MINGW)-gcc
MINGW_CXX = /usr/local/bin/$(MINGW)-g++

C_OPTS = \
	-nostdinc \
	-Os \
	$(DEFINES) $(INCLUDE)

CC_OPTS = $(C_OPTS) -std=gnu99

# Can't use c++11 because MinGW headers can't handle char16_t well
CXX_OPTS = $(C_OPTS) -std=c++03

CXX_OPTS_TEST = $(CXX_OPTS) -UBUILDING_OBJC -fobjc-arc


# AS = /usr/local/bin/$(MINGW)-gcc -c
AS = $(CC) $(TARGET)

AS_OPTS = -x assembler-with-cpp -I../include -Iruntime \
	$(DEFINES) $(INCLUDE)


LD = /usr/local/bin/$(MINGW)-g++
LD_LIBS =
LD_OPTS = $(LD_LIBS) -static


PRODUCT=test.exe
OBJS= \
	$(BUILD_OBJ_DIR)/maptable.o \
	$(BUILD_OBJ_DIR)/hashtable2.o \
	$(BUILD_OBJ_DIR)/objc-win32.o \
	$(BUILD_OBJ_DIR)/objc-msg-i386.o \
	$(BUILD_OBJ_DIR)/objc-runtime-new.o \
	$(BUILD_OBJ_DIR)/objc-class.o \
	$(BUILD_OBJ_DIR)/objc-errors.o \
	$(BUILD_OBJ_DIR)/objc-os.o \
	$(BUILD_OBJ_DIR)/Protocol.o \
	$(BUILD_OBJ_DIR)/NSObject.o \
	$(BUILD_OBJ_DIR)/objc-cache.o \
	$(BUILD_OBJ_DIR)/objc-runtime.o \
	$(BUILD_OBJ_DIR)/objc-sel.o \
	$(BUILD_OBJ_DIR)/objc-weak.o \
	$(BUILD_OBJ_DIR)/objc-sync.o \
	$(BUILD_OBJ_DIR)/objc-initialize.o \
	$(BUILD_OBJ_DIR)/objc-exception.o \
	$(BUILD_OBJ_DIR)/objc-references.o \
	$(BUILD_OBJ_DIR)/objc-opt.o \
	$(BUILD_OBJ_DIR)/objc-layout.o \
	$(BUILD_OBJ_DIR)/objc-loadmethod.o \
	$(BUILD_OBJ_DIR)/objc-typeencoding.o \
	$(BUILD_OBJ_DIR)/objc-sel-set.o \
	$(BUILD_OBJ_DIR)/test.o \
	$(BUILD_OBJ_DIR)/objc-sections-win32.o \


all: $(BUILD_OBJ_DIR) $(PRODUCT)

$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) -Wl,--script=objc-win32.ld $^ -o $@

$(BUILD_OBJ_DIR)/test.o: test.mm
	$(CC) $(CXX_OPTS_TEST) -fobjc-arc -fobjc-runtime=macosx -c $< -o $@

$(BUILD_OBJ_DIR)/objc-win32.o: runtime/objc-win32.cc
	$(MINGW_CXX) -x c++ $(CXX_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/objc-msg-i386.o: runtime/Messengers.subproj/objc-msg-i386.s
	$(AS) $(AS_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/objc-sections-win32.o: runtime/objc-sections-win32.s
	$(AS) $(AS_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/%.o: runtime/%.mm
	$(CC) $(CC_OBJCRT) $(CXX_OPTS) -c $< -o $@

clean:
	rm -f $(PRODUCT) $(BUILD_OBJ_DIR)/*
