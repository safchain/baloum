#include "all.h"

struct bpf_map_def SEC("maps/inodes") inodes = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = 256,
    .max_entries = 10,
};

struct open_data
{
    char filename[256];
};

struct bpf_map_def SEC("maps/cache") cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct open_data),
    .max_entries = 10,
};

SEC("kprobe/do_sys_open")
int BPF_KPROBE(kprobe_do_sys_open, int dfd, const char *filename, int flags, umode_t mode)
{
    struct open_data open_data = {};

    bpf_probe_read_str(open_data.filename, sizeof(open_data.filename), filename);

    u64 tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&cache, &tgid, &open_data, BPF_ANY);

    return 0;
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

    struct open_data *open_data = bpf_map_lookup_elem(&cache, &tgid);
    if (!open_data)
    {
        return 0;
    }

    bpf_map_update_elem(&inodes, &inode, open_data->filename, BPF_ANY);

    bpf_printk("Map: %s => %d(%d)\n", open_data->filename, inode, tgid);

    return 0;
};

SEC("kretprobe/do_sys_open")
int BPF_KRETPROBE(kretprobe_do_sys_open, int ret)
{
    u64 tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&cache, &tgid);

    return 0;
}

#ifdef __BALOUM__

#include "baloum.h"

SEC("test/ex1")
int test_ex1()
{
    // enter open syscall
    char *filename = "/etc/passwd";
    struct baloum_ctx ctx = {
        .arg1 = (u64)filename,
    };

    int ret = baloum_call(&ctx, "kprobe/do_sys_open");
    assert_zero(ret, "unable to call do_sys_open");

    u64 tgid = bpf_get_current_pid_tgid();

    struct open_data *open_data = bpf_map_lookup_elem(&cache, &tgid);
    assert_not_null(open_data, "cache entry not found");
    assert_strcmp(open_data->filename, filename, "filename not found");

    // vfs_open
    struct inode *inode = (struct inode *)baloum_malloc(sizeof(struct inode));
    inode->i_ino = 12345;

    struct dentry *dentry = (struct dentry *)baloum_malloc(sizeof(struct dentry));
    dentry->d_inode = inode;

    struct path *path = (struct path *)baloum_malloc(sizeof(struct path));
    path->dentry = dentry;

    ctx.arg0 = (u64)path;

    ret = baloum_call(&ctx, "kprobe/vfs_open");
    assert_zero(ret, "unable to call vfs_open");

    u64 ino = 12345;
    char *value = bpf_map_lookup_elem(&inodes, &ino);
    assert_not_null(value, "inodes entry not found");
    assert_strcmp(value, filename, "filename not found");

    // ret open syscall
    ret = baloum_call(&ctx, "kretprobe/do_sys_open");
    assert_zero(ret, "unable to call do_sys_open");

    open_data = bpf_map_lookup_elem(&cache, &tgid);
    assert_null(open_data, "cache entry found");

    return 0;
}

#endif

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;