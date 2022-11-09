#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

struct event
{
    u64 key;
    char value[16];
};

SEC("test/printk")
int test_printk()
{
    struct event event = {
        .key = 123,
        .value = "hello",
    };

    bpf_printk("this is a printk test, values: %d:%s", event.key, event.value);

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
