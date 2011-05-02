include Makefile.common
all: $(OUTDIR) $(OUTDIR)/libdata.a $(OUTDIR)/libdata.$(DYLIB)

$(OUTDIR):
	mkdir $(OUTDIR)
clean: .clean

$(OUTDIR)/%.o: %.c *.h
	$(GCC) -c -o $@ $< -Wreturn-type                              

OBJS := common.o binary.o running_kernel.o link.o find.o cc.o lzss.o 
OBJS := $(patsubst %,$(OUTDIR)/%,$(OBJS))

$(OUTDIR)/libdata.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $(OBJS)
$(OUTDIR)/libdata.$(DYLIB): $(OBJS)
	$(GCC) $(DYNAMICLIB) -o $@ $(OBJS)

