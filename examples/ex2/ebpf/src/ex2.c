#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

SEC("test/ex2")
int test_ex2()
{
    char text[32] = "text123";
    bpf_printk("The text is %s", text);

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;