
TRIPLE=i686-pc-win32
MINGW=i686-w64-mingw32

BUILD_DIR=build
BUILD_OBJ_DIR=$(BUILD_DIR)/$(TRIPLE)/objects

TARGET=-target $(TRIPLE)
INCLUDE= -Iinclude -I../include -I../include/objc \
	-isystem /usr/local/$(MINGW)/include \
	-isystem /usr/local/lib/gcc/$(MINGW)/4.9.0/include \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/ \
	-isystem /usr/local/$(MINGW)/include/c++/4.9.0/$(MINGW)

DEFINES=-D__OBJC2__=1 -DSUBJECTIVE=1 -DSUBJECTIVE_WIN32=1 -DBUILDING_OBJC \
	-DTARGET_OS_WIN32=1 -DTARGET_CPU_X86=1
CC_OTHER=-Wno-deprecated-objc-pointer-introspection -Wno-deprecated-objc-isa-usage -Wno-inline-new-delete -Wno-cast-of-sel-type -Wno-objc-root-class -Wno-duplicate-decl-specifier

CC = /usr/bin/clang
C_OPTS = $(TARGET) \
	-nostdinc -fobjc-runtime=macosx \
	-Os \
	$(DEFINES) $(INCLUDE) $(CC_OTHER)
CC_OPTS = $(C_OPTS) -std=gnu99
CXX_OPTS = $(C_OPTS) -std=c++03

AS=/usr/local/bin/$(MINGW)-gcc -c
AS=$(CC)
AS_OPTS=$(TARGET) -x assembler-with-cpp -I../include -Iruntime \
	$(DEFINES)

LD=/usr/local/bin/$(MINGW)-gcc
LD_OPTS=


PRODUCT=test.exe
OBJS= \
	$(BUILD_OBJ_DIR)/test.o \
	# $(BUILD_OBJ_DIR)/objc-msg-win32.o \
	# $(BUILD_OBJ_DIR)/objc-errors.o \
	# $(BUILD_OBJ_DIR)/NSObject.o \
	# $(BUILD_OBJ_DIR)/objc-class.o \
	# $(BUILD_OBJ_DIR)/objc-runtime-new.o \


all: $(BUILD_OBJ_DIR) $(PRODUCT)

$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) $^ -o $@

$(BUILD_OBJ_DIR)/test.o: test.mm
	$(CC) $(CXX_OPTS) -UBUILDING_OBJC -c $< -o $@

$(BUILD_OBJ_DIR)/objc-msg-win32.o: runtime/Messengers.subproj/objc-msg-win32.mm
	$(CC) $(CXX_OPTS) -c $< -o $@

$(BUILD_OBJ_DIR)/%.o: runtime/%.mm
	$(CC) $(CXX_OPTS) -c $< -o $@

clean:
	rm -f $(PRODUCT) $(BUILD_OBJ_DIR)/*
