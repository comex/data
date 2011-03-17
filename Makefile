all: libdata.a

GCC ?= /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.3.sdk/ -mapcs-frame -fomit-frame-pointer -mthumb -fno-builtin-printf -fno-builtin-memset
CFLAGS ?= -g3 -std=gnu99 -Os -Wall -Wextra -Wno-parentheses -Werror
ifneq ($(strip $(wildcard /usr/include/CommonCrypto)),)
CFLAGS += -DIMG3_SUPPORT -dead_strip
endif
AR ?= ar

%.o: %.c *.h
	$(GCC) $(CFLAGS) -c -o $@ $< -Wreturn-type                              

libdata.a: common.o binary.o running_kernel.o link.o find.o cc.o lzss.o 
	$(AR) rcs $@ $^

check_sanity: libdata.a check_sanity.o
	$(GCC) $(CFLAGS) -o $@ check_sanity.o -L. -ldata

clean:
	rm -f *.o libdata.a check_sanity
