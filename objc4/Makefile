
TRIPLE=i686-pc-win32
MINGW=i686-w64-mingw32

BUILD_DIR=build
BUILD_OBJ_DIR=$(BUILD_DIR)/$(TRIPLE)/objects

TARGET=-target $(TRIPLE)
INCLUDE= -I../include -I../include/objc \
	-isystem /usr/local/$(MINGW)/include \
	-isystem /usr/local/lib/gcc/$(MINGW)/4.9.0/include \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/ \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/$(MINGW)

DEFINES=-DSUBJECTIVE=1 -D_X86_
CC_OTHER=-Wno-deprecated-objc-pointer-introspection -Wno-deprecated-objc-isa-usage -Wno-inline-new-delete -Wno-cast-of-sel-type -Wno-objc-root-class -Wno-duplicate-decl-specifier

CC=/usr/bin/clang
CC_OPTS= $(TARGET) \
	-std=c++03 \
	-nostdinc -fblocks -fobjc-runtime=macosx \
	-Os \
	$(DEFINES) $(INCLUDE) $(CC_OTHER)

AS=/usr/local/bin/$(MINGW)-gcc -c
AS=$(CC)
AS_OPTS=$(TARGET) -x assembler-with-cpp -I../include -Iruntime \
	$(DEFINES)

LD=/usr/local/bin/$(MINGW)-gcc
LD_OPTS=


PRODUCT=test.exe
OBJS= \
	$(BUILD_OBJ_DIR)/test.o \
	$(BUILD_OBJ_DIR)/objc-msg-i386.o \
	$(BUILD_OBJ_DIR)/objc-class.o \


all: $(BUILD_OBJ_DIR) $(PRODUCT)

$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) $^ -o $@

$(BUILD_OBJ_DIR)/test.o: test.mm
	$(CC) $(CC_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/objc-msg-i386.o: runtime/Messengers.subproj/objc-msg-i386.s
	$(AS) $(AS_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/%.o: runtime/%.mm
	$(CC) $(CC_OPTS) -c $< -o $@

clean:
	rm -f $(PRODUCT) $(BUILD_OBJ_DIR)/*
