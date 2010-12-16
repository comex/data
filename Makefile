all: white_loader

GCC ?= /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.2.sdk/ -mapcs-frame -fomit-frame-pointer -mthumb -fno-builtin-printf -fno-builtin-memset
CFLAGS ?= -g3 -std=gnu99 -Os -Wall -Wextra -Wno-parentheses -Werror
ifneq ($(strip $(wildcard /usr/include/CommonCrypto)),)
CFLAGS += -DIMG3_SUPPORT -dead_strip
endif
AR ?= ar

%.o: %.c *.h
	$(GCC) $(CFLAGS) -c -o $@ $< -Wreturn-type                              

libdata.a: common.o binary.o running_kernel.o link.o find.o cc.o lzss.o 
	$(AR) rcs $@ $^

white_loader: libdata.a white_loader.o
	$(GCC) $(CFLAGS) -o $@ white_loader.o -L. -ldata
ifneq ($(shell which lipo),)
	bash -c 'if [ -n "`lipo -info $@ | grep arm`" ]; then ldid -Sent.plist $@; fi'
endif
	
clean:
	rm -f *.o libdata.a white_loader
