include Makefile.common
all: $(OUTDIR) $(OUTDIR)/libdata.a $(OUTDIR)/libdata.$(DYLIB)

$(OUTDIR):
	mkdir -p $(OUTDIR) $(OUTDIR)/mach-o $(OUTDIR)/dyldcache
clean: .clean

OBJS := common.o binary.o running_kernel.o find.o cc.o lzss.o mach-o/binary.o mach-o/link.o mach-o/inject.o dyldcache/binary.o
OBJS := $(patsubst %,$(OUTDIR)/%,$(OBJS))

$(OUTDIR)/libdata.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $(OBJS)
$(OUTDIR)/libdata.$(DYLIB): $(OBJS)
	$(GCC) $(DYNAMICLIB) -o $@ $(OBJS)

