#include "all.h"

#ifdef __BALOUM__

#include "baloum.h"

struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 0,
    .pinning = 0,
    .namespace = "",
};

struct event
{
    u64 key;
    u64 value;
};

SEC("test/perf")
int test_perf()
{
    struct pt_regs ctx = {};

    struct event event = {
        .key = 123,
        .value = 456,
    };

    return bpf_perf_event_output(&ctx, &events, 0, &event, sizeof(event));
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
