
TRIPLE = i686-pc-win32
MINGW = i686-w64-mingw32

# The following is for the <*intrin.h>
CLANG_TOOLCHAIN_DIR=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/5.1

BUILD_DIR = build

BUILD_OBJ_DIR = $(BUILD_DIR)/$(TRIPLE)/objects

TARGET = -target $(TRIPLE)

INCLUDE = -Iinclude -I../include -I../include/objc \
	-isystem $(CLANG_TOOLCHAIN_DIR)/include \
	-isystem /usr/local/$(MINGW)/include \
	-isystem /usr/local/lib/gcc/$(MINGW)/4.9.0/include \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/ \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/$(MINGW)

DEFINES = -D__OBJC2__=1 -DSUBJECTIVE=1 -DSUBJECTIVE_WIN32=1 \
	-DBUILDING_OBJC -DTARGET_OS_WIN32=1 -DTARGET_CPU_X86=1 -D_X86_ \
	-DWIN32

CC_OTHER = -Wno-deprecated-objc-pointer-introspection \
	-Wno-deprecated-objc-isa-usage -Wno-inline-new-delete \
	-Wno-cast-of-sel-type -Wno-objc-root-class \
	-Wno-duplicate-decl-specifier

CC = /usr/bin/clang

C_OPTS = $(TARGET) \
	-nostdinc -fobjc-runtime=macosx \
	-Os \
	-fno-ms-compatibility \
	$(DEFINES) $(INCLUDE) $(CC_OTHER)

CC_OPTS = $(C_OPTS) -std=gnu99

CXX_OPTS = $(C_OPTS) -std=c++11

CXX_OPTS_TEST = $(CXX_OPTS) -UBUILDING_OBJC -fobjc-arc


AS = /usr/local/bin/$(MINGW)-gcc -c

AS = $(CC)

AS_OPTS = $(TARGET) -x assembler-with-cpp -I../include -Iruntime \
	$(DEFINES) $(INCLUDE)


LD = /usr/local/bin/$(MINGW)-g++
LD_OPTS = $(LD_LIBS)


PRODUCT=test.exe
OBJS= \
	$(BUILD_OBJ_DIR)/test.o \
	$(BUILD_OBJ_DIR)/maptable.o \
	$(BUILD_OBJ_DIR)/hashtable2.o \
	$(BUILD_OBJ_DIR)/objc-errors.o \
	$(BUILD_OBJ_DIR)/objc-msg-i386.o \
	$(BUILD_OBJ_DIR)/objc-os.o \
	$(BUILD_OBJ_DIR)/Protocol.o \
	$(BUILD_OBJ_DIR)/NSObject.o \
	$(BUILD_OBJ_DIR)/objc-cache.o \
	$(BUILD_OBJ_DIR)/objc-runtime.o \
	$(BUILD_OBJ_DIR)/objc-runtime-new.o \
	$(BUILD_OBJ_DIR)/objc-class.o \
	$(BUILD_OBJ_DIR)/objc-sel.o \
	$(BUILD_OBJ_DIR)/objc-weak.o \
	$(BUILD_OBJ_DIR)/objc-sync.o \
	$(BUILD_OBJ_DIR)/objc-initialize.o \
	$(BUILD_OBJ_DIR)/objc-exception.o \
	$(BUILD_OBJ_DIR)/objc-references.o \
	$(BUILD_OBJ_DIR)/objc-opt.o \
	$(BUILD_OBJ_DIR)/objc-layout.o \
	$(BUILD_OBJ_DIR)/objc-loadmethod.o \


all: $(BUILD_OBJ_DIR) $(PRODUCT)

$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) $^ -o $@

$(BUILD_OBJ_DIR)/test.o: test.mm
	$(CC) $(CXX_OPTS_TEST) -c $< -o $@

$(BUILD_OBJ_DIR)/objc-msg-i386.o: runtime/Messengers.subproj/objc-msg-i386.s
	$(AS) $(AS_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/%.o: runtime/%.mm
	$(CC) $(CXX_OPTS) -c $< -o $@

clean:
	rm -f $(PRODUCT) $(BUILD_OBJ_DIR)/*
