
TRIPLE=i686-w64-mingw32
PREFIX=/usr/local/
CC=/usr/bin/clang
AS=$(PREFIX)/bin/$(TRIPLE)-gcc
LD=$(PREFIX)/bin/$(TRIPLE)-gcc
STRIP=$(PREFIX)/bin/$(TRIPLE)-strip
ISYSTEM=$(PREFIX)/$(TRIPLE)/include

BUILD_DIR=build
BUILD_OBJ_DIR=$(BUILD_DIR)/$(TRIPLE)/objects

CC=clang

CC_OPTS= \
	-cc1 -triple $(TRIPLE) \
	-O2 \
	-isystem $(ISYSTEM)

LD_OPTS=

PRODUCT=test.exe
OBJS=$(BUILD_OBJ_DIR)/test.obj


all: $(BUILD_OBJ_DIR) $(PRODUCT)


$(BUILD_OBJ_DIR):
	mkdir -p $(BUILD_OBJ_DIR)

$(BUILD_OBJ_DIR)/%.s: %.mm
	$(CC) $(CC_OPTS) -S $< -o $@

$(BUILD_OBJ_DIR)/%.obj: $(BUILD_OBJ_DIR)/%.s
	$(AS) $(AS_OPTS) -c $< -o $@

$(PRODUCT): $(OBJS)
	$(LD) $(LD_OPTS) $< -o $@


clean:
	rm -f *.exe $(BUILD_OBJ_DIR)/*
