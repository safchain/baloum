#include "all.h"

#ifdef __baloum__

#include "baloum.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

SEC("test/array")
int test_array()
{
    u64 key = 4;
    u64 *entry = bpf_map_lookup_elem(&cache, &key);
    if (!entry)
    {
        return -1;
    }

    *entry = 44;

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
