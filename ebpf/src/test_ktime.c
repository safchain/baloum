#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

SEC("test/ktime")
int test_ktime()
{
    u64 ns = bpf_ktime_get_ns();
    if (ns == 44)
    {
        return 0;
    }
    return -1;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
