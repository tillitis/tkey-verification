
# We expect our apps repo cloned as a sibling to this
APPSREPOAPPS=../../tillitis-key1-apps/apps

OBJCOPY ?= llvm-objcopy

CC = clang

INCLUDE=$(APPSREPOAPPS)/include

# NOTE: The following note is not valid, you'd have to edit
# $(APPSREPOAPPS)/Makefile somehow:
# If you want libcommon's qemu_puts() et cetera to output something on our QEMU
# debug port, remove -DNODEBUG below
CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -Wall -flto -I $(INCLUDE) -I $(APPSREPOAPPS) -DNODEBUG

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS=-T $(APPSREPOAPPS)/app.lds -L $(APPSREPOAPPS)/libcommon/ -lcommon -L $(APPSREPOAPPS)/libcrt0/ -lcrt0

RM=/bin/rm


.PHONY: all
all: verisigner/app.bin

.PHONY: appsrepo
appsrepo:
	cd $(APPSREPOAPPS) && make libcommon/libcommon.a libcrt0/libcrt0.a monocypher/libmonocypher.a

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-verisigner-hash: verisigner/app.bin
	cd verisigner && sha512sum app.bin

check-verisigner-hash: verisigner/app.bin
	cd verisigner && sha512sum -c app.bin.sha512

# verisigner-app, our signer-app fork for verification
VERISIGNEROBJS=verisigner/main.o verisigner/app_proto.o
verisigner/app.elf: appsrepo $(VERISIGNEROBJS)
	$(CC) $(CFLAGS) $(VERISIGNEROBJS) $(LDFLAGS) -L $(APPSREPOAPPS)/monocypher -lmonocypher -I $(APPSREPOAPPS)/monocypher -o $@
$(VERISIGNEROBJS): verisigner/app_proto.h

.PHONY: clean
clean:
	$(RM) -f verisigner/app.bin verisigner/app.elf $(VERISIGNEROBJS)
	cd $(APPSREPOAPPS) && make clean

# Uses ../.clang-format
FMTFILES=verisigner/*.[ch]
.PHONY: fmt
fmt:
	clang-format --dry-run --ferror-limit=0 $(FMTFILES)
	clang-format --verbose -i $(FMTFILES)
.PHONY: checkfmt
checkfmt:
	clang-format --dry-run --ferror-limit=0 --Werror $(FMTFILES)
