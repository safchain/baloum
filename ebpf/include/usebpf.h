#ifdef __USEBPF__

#ifndef _USEBPF_H__
#define _USEBPF_H__

struct usebpf_ctx
{
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
};
static void *(*usebpf_malloc)(__u32 size) = (void *)0xffff;
static int (*usebpf_call)(struct usebpf_ctx *ctx, const char *section) = (void *)0xfffe;
static int (*usebpf_strcmp)(const char *str1, const char *str2) = (void *)0xfffd;

#endif

#endif