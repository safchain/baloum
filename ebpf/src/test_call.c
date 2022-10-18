#include "all.h"

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10,
};

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, struct path *path)
{
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    u64 inode;
    bpf_probe_read(&inode, sizeof(inode), &d_inode->i_ino);

    u64 tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&cache, &tgid, &inode, BPF_ANY);

    return 0;
};

SEC("kretprobe/vfs_open")
int BPF_KRETPROBE(kretprobe_vfs_open, int ret)
{
    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&cache, &tgid);

    return 0;
}

#ifdef __USEBPF__

#include "usebpf.h"

SEC("test/simple_call")
int test_simple_call()
{
    struct inode *inode = (struct inode *)usebpf_malloc(sizeof(struct inode));
    inode->i_ino = 12345;

    struct dentry *dentry = (struct dentry *)usebpf_malloc(sizeof(struct dentry));
    dentry->d_inode = inode;

    struct path *path = (struct path *)usebpf_malloc(sizeof(struct path));
    path->dentry = dentry;

    struct usebpf_ctx ctx = {
        .arg0 = (u64)path,
    };

    int ret = usebpf_call(&ctx, "kprobe/vfs_open");
    if (ret != 0)
    {
        return -1;
    }

    return 0;
}

SEC("test/nested_call")
int test_all()
{
    struct usebpf_ctx ctx = {};

    int ret = usebpf_call(&ctx, "test/simple_call");
    if (ret != 0)
    {
        return -1;
    }

    u64 tgid = bpf_get_current_pid_tgid();

    u64 *inode = bpf_map_lookup_elem(&cache, &tgid);
    if (!inode || *inode != 12345)
    {
        return -1;
    }

    ret = usebpf_call(&ctx, "kretprobe/vfs_open");
    if (ret != 0)
    {
        return -1;
    }

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
