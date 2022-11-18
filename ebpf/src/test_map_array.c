#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

struct bpf_map_def SEC("maps/cache64") cache64 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/cache32") cache32 = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/cache_cpu") cache_cpu = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

SEC("test/array64")
int test_array64()
{
    u64 key = 4;
    u64 *entry = bpf_map_lookup_elem(&cache64, &key);
    if (!entry)
    {
        return -1;
    }

    *entry = 44;

    return 0;
}

SEC("test/array32")
int test_array32()
{
    u32 key = 4;
    u32 *entry = bpf_map_lookup_elem(&cache32, &key);
    if (!entry)
    {
        return -1;
    }

    *entry = 44;

    return 0;
}

SEC("test/array_cpu")
int test_array_cpu()
{
    u64 key = 4;
    u64 *entry = bpf_map_lookup_elem(&cache_cpu, &key);
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
