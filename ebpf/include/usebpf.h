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
static int (*usebpf_strcmp)(const char *s1, const char *s2) = (void *)0xfffd;
static int (*usebpf_memcmp)(const void *b1, const void *b2, __u32 size) = (void *)0xfffc;

#define assert_memcmp(b1, b2, s, msg)                                \
    if (usebpf_memcmp(b1, b2, s) != 0)                               \
    {                                                                \
        bpf_printk("assert line %d : b1 != b2 : %s", __LINE__, msg); \
        return -1;                                                   \
    }

#define assert_strcmp(s1, s2, msg)                                   \
    if (usebpf_strcmp(s1, s2) != 0)                                  \
    {                                                                \
        bpf_printk("assert line %d : s1 != s2 : %s", __LINE__, msg); \
        return -1;                                                   \
    }

#define assert_equals(v1, v2, msg)                                   \
    if (v1 != v2)                                                    \
    {                                                                \
        bpf_printk("assert line %d : v1 != v2 : %s", __LINE__, msg); \
        return -1;                                                   \
    }

#define assert_zero(v1, msg)                                           \
    if (v1 != 0)                                                       \
    {                                                                  \
        bpf_printk("assert line %d : v1 == NULL : %s", __LINE__, msg); \
        return -1;                                                     \
    }

#define assert_not_equals(v1, v2, msg)                               \
    if (v1 == v2)                                                    \
    {                                                                \
        bpf_printk("assert line %d : v1 == v2 : %s", __LINE__, msg); \
        return -1;                                                   \
    }

#define assert_not_null(v1, msg)                                       \
    if (v1 == NULL)                                                    \
    {                                                                  \
        bpf_printk("assert line %d : v1 == NULL : %s", __LINE__, msg); \
        return -1;                                                     \
    }

#define assert_null(v1, msg)                                           \
    if (v1 != NULL)                                                    \
    {                                                                  \
        bpf_printk("assert line %d : v1 != NULL : %s", __LINE__, msg); \
        return -1;                                                     \
    }

#endif

#endif