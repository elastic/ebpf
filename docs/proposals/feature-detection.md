# Feature detection for eBPF

## Privileges

To build a machinery that does full feature detection requires specific **privileges**.

Namely, it requires `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`.
If the kernel does not know about `CAP_BPF`, such a machinery requires `CAP_SYS_ADMIN`.

Anyways, detecting unprivileged eBPF features can be done without the full privileges (it would require `libcap`).

So, the first aspect to keep in mind is: **privileges**.

## Features

Then, there is the **feature** aspect.

We should also distinguish between Kernel configurations and eBPF features. Often, the latter depends on the former.

I envision the following **categories** of checks:

1. system configurations (requires procfs)
   1. check unprivileged eBPF is disabled (`/proc/sys/kernel/unprivileged_bpf_disabled`)
   2. check JIT
      1. enable (`/proc/sys/net/core/bpf_jit_enable`)
      2. harden (`/proc/sys/net/core/bpf_jit_harden`)
      3. kallsysm (`/proc/sys/net/core/bpf_jit_kallsyms`)
      4. limit (`/proc/sys/net/core/bpf_jit_limit`)
   3. check kernel image (`/boot/config-*`, `/proc/config.gz`) for:
      1. `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, `CONFIG_HAVE_EBPF_JIT`, `CONFIG_BPF_JIT`, `CONFIG_BPF_JIT_ALWAYS_ON`
      2. `CONFIG_DEBUG_INFO_BTF`, `CONFIG_DEBUG_INFO_BTF_MODULES`
      3. etc.
2. syscall configuration
   1. try to load a `BPF_PROG_TYPE_UNSPEC` with `bpf` syscall and grab the result
3. supported program types
   1. Use `bpf_probe_prog_type` of `libbpf` (present since v0.0.2) or equivalent implementation
      1. It loads an eBPF program type (depending on the program type to probe) composed of 2 instructions (`MOV64_IMM(r0, 0)`, `EXIT_INSN()`)
      2. Checks the outcome
   2. For unprivileged case, check that `errno` is not `EPERM` (insufficient permissions)
4. supported map types
   1. Use `bpf_probe_map_type` of `libbpf` (present since v0.0.2) or equivalent implementation
5. supported helper types by program type
   1. Use `bpf_probe_helper` of `libbpf` (present since v0.0.2)
      1. It loads an eBPF program (of the type for which to probe the helper/s) composed of 2 instructions (`EMIT_CALL(helper_id)`, `EXIT_INSN()`)
      2. Checks the outcome
   2. Only account for offloadable program types when targeting a device
   3. Future:
      1. notice that some helper functions emit dmesg messages (eg., `BPF_FUNC_trace_printk`), we may want to separate them from the rest
      2. whether an helper is GPL-only or not: requires reading the `_proto` kernel structs
6. others miscellaneous features
   1. Detect whether programs up to `BPF_MAXINSNS` instructions are supported
      1. Use `bpf_probe_large_insn_limit` of `libbpf` (present since v0.0.7) or equivalent implementation
         1. Especially useful when targeting a device

## Targets

Finally, it is imporant noticing that the third and last aspect to consider is the **target** we are probing.

It's important to distinguish whether these checks have to run against a device.

We have 2 possible **targets** for this API: kernel or device.

## API

To me, we do have basically two possible API designs available (**not mutually exclusive since the second can generate the first**).

### Preprocessing/compilation time

We may build a machinery that runs steps 1-6 and it generates a **C header** containing macros/defines for the various system configurations and eBPF features
detected on the current kernel/device target.

Then we could simply include such C header and use it in our programs.

```c
#define HAS_BPF_SYSCALL
// ...
#define HAS_KPROBE_PROG_TYPE
#define HAS_SCHED_CLS_PROG_TYPE
// ...
#define HAS_HASH_MAP_TYPE
#define HAS_ARRAY_MAP_TYPE
// ...
#define PROG_TYPE_HAS_HELPER(prog_type, helper) \
    PROG_TYPE_ ## prog_type ## __HAS_HELPER ## helper
// ...
#define PROG_TYPE_lsm__HAS_HELPER_bpf_tail_call 0
```

***Cons***:

- Such a header would need to be generated on the target kernel
  - I believe this is a **blocker** for us
  - It makes no sense to talk about BTF and CO-RE if then we still need to generate headers for different target kernels
- Very verbose, especially in case we end up defining macro variations for the unprivileged case too and for different targets.

***Pros***:

- It is the approach more commonly used in eBPF land (as of today at least)

### Runtime

#### Stateless lower-level API

We may build a API like the following (in pseudo-code):

```c
bool can_bpf(bool unprivileged, u32 if_idx);
bool has_map(u32 map_type, bool unprivileged, u32 if_idx);
bool has_prog(u32 prog_type, bool unprivileged, u32 if_idx);
bool has_helper_for_prog(string helper, u32 prog_type, bool unprivileged, u32 if_idx);
// ...
```

Such an API would be called like so (pseudo-code):

```c
has_map(BPF_MAP_TYPE_LPM_TRIE, false, 0);
has_prog(BPF_PROG_TYPE_LSM, false, 0);
has_prog(BPF_PROG_TYPE_SCHED_CLS, false, 2/*eth0*/);
has_prog(BPF_PROG_SOCKET_FILTER, true, 0);
has_helper_for_prog("bpf_get_stackid", BPF_PROG_TYPE_TRACING, false, 0);
```

Some observations.

**Targets**:

This API has 2 targets: **kernel** or **device**.

The `if_idx` argument is only relevant when greater than 0, pointing to a device interface (device target, eg. 1 being `lo` iface, 2, etc.).
Otherwise, and by default, the API probes the kernel (kernel target).

**Usage observations**:

Notice such an API is meant to be called from the loader of an eBPF program, not from within an eBPF program.

Turns out,
this means we may ending up writing different eBPF programs for the same feature with different implementation (eg., perf buffer vs ring buffer)
and load one or the other depeding on the feature existence we detect before loading.

I personally consider this a +1 because I do believe it would force us to write more self-contained eBPF programs without `ifdefs` or `if` chain hells.

Anyways, in case we would like to use this API in an eBPF program, we could nevertheless.
By following these steps:

1. detect the feature we need for the eBPF program we are about to load
2. populate the `rodata` section (one or more `const` variables in the eBPF program)
3. write the eBPF program to react to those `const` variables at runtime

This way we may write a single eBPF program that, depending on the conditions on those variables, uses one feature or the other.
Notice that global data sections for eBPF programs requires kernel 5.2. But the same overall behavior can be achieved with plain eBPF maps.

**Unprivileged probing**:

If the API user wants to explicitly probe feature existence for unprivileged use case while it has the full privileges,
the API should in that case lower the privileges is using. Then, proceed as normal.

Also the reverse can happen. An API user with low privileges that wants to probe eBPF features requiring more privileges.

In such case, I advice to just return `false` for the specific feature being probed even if we can't really know if it would be available with more privileges or not.

**System configs**:

Point 1 of the above list.

This step needs procfs to parse the sysctl knobs that govern some eBPF features.

Also, it needs to parse the kernel config.

To avoid writing a parser for the Kernel config, a easier/cleaner approach
would be to write an eBPF program that uses **Kconfig externs** to probe the Kernel configs and then stores such values in a pinned map.
By loading this probe at the start of our future programs pipeline, we can avoid parsing multiple times the Kernel config (read below).

But such approach requires anyways the Kernel config (eg., `/proc/config.gz`).

Anyways, for the sake of completeness, this is how **Kconfig externs** are used:

```c
extern enum libbpf_tristate CONFIG_BPF_PRELOAD __kconfig __weak;

switch (CONFIG_BPF_PRELOAD) {
    case TRI_NO: ...; break;
    case TRI_YES: ...; break;
    case TRI_MODULE: ...; break;
}
```

On the API side, nothing changes disregarding whether we implement this in BPF or not.

**Interdependence and composition**:

Let's say that we wanna know whether we can load and execute BPF LSM on a specific Kernel.

To do so, we'd need to check various things at system configuration level (point 1), for example whether BTF is enabled or not first of all, and then at other levels too (`BPF_PROG_TYPE_LSM`).

So, it could make sense to build a **stateful layer on top of this stateless API**.

An initialization step that grabs (and stores/caches) the kernel config values to avoid having to parse for them again (disregarding how we implement this, see above).

There are cases in which it can be pretty useful to have all the needed values in place.
In fact, it is also very common that a Kernel config depends on other Kernel configs (see `config BPF_LSM` for example, [link](https://github.com/torvalds/linux/blob/5d6ab0bb408ffdaac585982faa9ec8c7d5cc349f/kernel/bpf/Kconfig#L77)).

So, we can define DAGs (or FSMs) to declaratively express feature detection at **an higher granularity level**.

And expose those DAGs via a public API (eg. `has_bpf_lsm()`) that compose all the necessary checks on the various values, whether they are at system configuration level or at another level.

For example, in the case of BPF LSM, we may compose a finite-state machine that would look like this:

![2021-11-15-17-19-44](https://user-images.githubusercontent.com/120051/141838763-78feb945-a623-4279-ab47-b02d1b3893c8.png)

Notice that to understand the LSM support we need to check whether the `lsm=...,bpf` has been declared in the Kernel configs or in the Kernel boot parameters (LR_2 to LR_3 edge) too.

**Support for map/program/helpers**:

Points 5 in the above list suggests using the `bpf_probe_helper` function (in the cases of helpers), which basically emits a call instruction towards the ID of the helper.
And later check the success of the operation.

In a similar way, for detecting supported eBPF maps and supported eBPF program types.

It's worth noting that, in case the target system has BTF, there is a more idiomatic way of doing this via BTF:

```c
if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ringbuf_reserve)) {
    // use bpf_ringbuf_reserve()
} else {
    // fallback to bpf_perf_event_output()
}
```

Ipothetically, a top layer API, rather than issuing a call instruction to test the availability of a given helper,
may simply use BTF knowing it's available.

Fallbacking to the one based on instructions when BTF is not there.

Notice that the same mechanism can be used for map and program types too.
Notice also that this same mechanism can be used also for non-BPF things.

#### Stateful higher-level API

The 2/3 previous observations show how we need to operate at two different layers, IMO.

To wrap up, I'd propose a top-level API providing shortcut functions to asses the presence of very well know (sets of) eBPF features representing them like DAGs or FSMs:

```c
bool has_bpf_lsm();
// ...
```

#### Naming


All I described can be a nice public library named **bpfhaz** or **hazbpf**.

![2021-11-15-16-11-02](https://user-images.githubusercontent.com/120051/141838622-a53501d9-5427-43c1-a375-b1ca8ccd3aad.png)

That we use ourselves.
