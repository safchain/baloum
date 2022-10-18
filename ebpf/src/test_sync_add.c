#include "all.h"

#ifdef __USEBPF__

#include "usebpf.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

SEC("test/sync_add")
int test_sync_add()
{
    u64 key = 4;
    u64 *entry = bpf_map_lookup_elem(&cache, &key);
    if (!entry)
    {
        return -1;
    }

    __sync_fetch_and_add(entry, 14);

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
