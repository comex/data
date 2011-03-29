include Makefile.common
all: .settings libdata.a libdata.$(DYLIB)

%.o: %.c *.h
	$(GCC) $(CFLAGS) -c -o $@ $< -Wreturn-type                              

OBJS := common.o binary.o running_kernel.o link.o find.o cc.o lzss.o 
libdata.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $(OBJS)
libdata.$(DYLIB): $(OBJS)
	$(GCC) $(DYNAMICLIB) -o $@ $(OBJS)

clean:
	rm -f *.o libdata.a
