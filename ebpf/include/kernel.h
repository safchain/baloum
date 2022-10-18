#ifndef _KERNEL_H__
#define _KERNEL_H__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#pragma clang diagnostic pop

#endif
