SRCS = $(wildcard src/*.c)
PROGS = $(patsubst src/%.c, bin/%.o, $(SRCS))

all: $(PROGS)

src/%.c: include/usebpf.h

bin/%.o: src/%.c
	mkdir -p bin
	clang-12 -D__KERNEL__ -D__ASM_SYSREG_H -D__USEBPF__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I include \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		$< \
		-c -o - | llc -march=bpf -filetype=obj -o $@