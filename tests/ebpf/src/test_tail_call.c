#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

struct bpf_map_def SEC("maps/data") data = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps/tail_calls") tail_calls = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

SEC("test/tail_call_prog")
int tail_call_prog(struct pt_regs *ctx) {
    u64 key = 0;
    char *entry = bpf_map_lookup_elem(&data, &key);
    if (!entry)
    {
        return -1;
    }
    *entry += 10;

    return 72;
}

SEC("test/tail_call")
int test_tail_call()
{
    struct pt_regs ctx = {};

    bpf_tail_call(&ctx, &tail_calls, 0);

    // shouldn't be executed
    u64 key = 0;
    char *entry = bpf_map_lookup_elem(&data, &key);
    if (!entry)
    {
        return -1;
    }
    *entry = 55;

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
