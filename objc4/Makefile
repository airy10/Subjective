
TRIPLE=i686-pc-win32

BUILD_DIR=build
BUILD_OBJ_DIR=$(BUILD_DIR)/$(TRIPLE)/objects

TARGET=-target $(TRIPLE)
INCLUDE= -I../include -I../include/objc \
	-isystem /usr/local/i686-w64-mingw32/include \
	-isystem /usr/local/lib/gcc/i686-w64-mingw32/4.9.0/include \
	-isystem /usr/local/i686-w64-mingw32/include/c++/4.9.0/ \
	-isystem /usr/local/i686-w64-mingw32/include/c++/4.9.0/i686-w64-mingw32

DEFINES=-DSUBJECTIVE=1 -D_X86_

CC=/usr/bin/clang
CC_OPTS= $(TARGET) \
	-std=c++03 \
	-nostdinc -fobjc-runtime=macosx -m32 \
	-Os \
	$(DEFINES) $(INCLUDE)


LD=/usr/local/bin/i686-w64-mingw32-gcc
LD_OPTS=

PRODUCT=test.exe
OBJS= \
	$(BUILD_OBJ_DIR)/test.o \
	$(BUILD_OBJ_DIR)/objc-msg-i386.o \


all: $(BUILD_OBJ_DIR) $(PRODUCT)

$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) $< -o $@

$(BUILD_OBJ_DIR)/test.o: test.mm
	$(CC) $(CC_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/objc-msg-i386.o: runtime/Messengers.subproj/objc-msg-i386.s
	$(CC) $(CC_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/%.o: runtime/%.mm
	$(CC) $(CC_OPTS) -c $< -o $@

clean:
	rm -f $(PRODUCT) $(BUILD_OBJ_DIR)/*
