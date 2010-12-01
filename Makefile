all: white_loader

GCC ?= /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.1.sdk/ -mapcs-frame -fomit-frame-pointer -mthumb -fno-builtin-printf -fno-builtin-memset
CFLAGS ?= -g3 -std=gnu99 -Os -Wall -Wno-parentheses -Werror
AR ?= ar

%.o: %.c *.h
	$(GCC) $(CFLAGS) -c -o $@ $< -DIMG3_SUPPORT -Wreturn-type                              

libdata.a: common.o binary.o running_kernel.o link.o find.o cc.o lzss.o 
	$(AR) rcs $@ $^

white_loader: libdata.a white_loader.o
	$(GCC) -o $@ $^
	bash -c 'if [ -n "`lipo -info $@ | grep arm`" ]; then ldid -Sent.plist $@; fi'
	
clean:
	rm -f *.o libdata.a white_loader
