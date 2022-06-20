# eBPF
[![Build Status](https://github.com/elastic/ebpf/workflows/eBPF%20CI/badge.svg)](https://github.com/elastic/ebpf/actions)

Collection of BPF programs for Linux.

- [Host Isolation](#host-isolation)
## Host Isolation

### Programs

- **KprobeConnectHook** hooks into tcp_v4_connect and adds destination IP to allowlist if PID is allowed
- **TcFilter** attaches to network interface and filters packets based on allowed IPs

### Demo

- **UpdateIPsDemo** Userspace tool for updating IP and subnet allowlist
- **UpdatePidsDemo** Userspace tool for updating PID allowlist
- **KprobeConnectHookDemo** Loader for KprobeConnectHook eBPF program
- **TcLoaderDemo** Loader for TcFilter eBPF program, attaches to ens33 interface by default

<details>
  <summary>Run the demos</summary>

1. Follow the build section to build the project so that you have the `build/` folder
1. Run `cd build/target/ebpf`
1. Run `sudo ../../non-GPL/TcLoader/TcLoaderDemo` - packet filter is now attached to ens33
1. Run `sudo ../../non-GPL/HostIsolation/KprobeConnectHook/KprobeConnectHookDemo` - connect hook is attached
1. Run `firefox` in another tab - verify that all internet access is blocked
1. Run `pgrep firefox` to get the PID of the browser
1. Run `sudo ../../non-GPL/HostIsolationMapsUtil/UpdatePidsDemo <firefox PID>`
1. Verify that firefox connects to any page
1. Quit KprobeConnectHook with Ctrl+C and run `sudo ../../non-GPL/TcLoader/TcLoaderDemo unload` to detach both eBPF programs

</details>

### Tests (BPF_PROG_TEST_RUN)

#### BPFTcFilterTests

`BPFTcFilterTests` test suite for the `TcFilter.bpf.o` program

**Usage**

```bash
cd build/target/ebpf
sudo ../test/BPFTcFilterTests
```

Or if you want to use a custom path for the eBPF object file.

```bash
sudo ELASTIC_EBPF_TC_FILTER_OBJ_PATH=build/target/ebpf/TcFilter.bpf.o  build/target/test/BPFTcFilterTests
```


## Build dependencies
Some distros might not have bmake
or an older CMake, compiling them from source is usually a good alternative.

bmake is the NetBSD make tool and it's used to build elftoolchain's libelf, the BSD Licensed ELF library
we use as alternative to the GNU/Linux licensed elfutils's libelf.

**Ubuntu/Debian**

```bash
apt install clang llvm cmake bmake zlib1g-dev m4 gcc g++ libc6-dev-i386
```

**CentOS/Fedora/AL2**

```
yum install gcc g++ clang llvm zlib-devel m4 bmake
```

## Build

The build is a pretty standard CMake project.

```
mkdir build
cd build
cmake ..
make
```

Besides the usual CMake variables, you can set the following variables which are specific to this project.

| Variable         | Description                                                                |
| ---------------- | -------------------------------------------------------------------------- |
| -DTARGET_DIR     | Directory to use to store the compiled targets                             |
| -DLIBBPF_CONTRIB | Alternative directory to use for libbpf sources instead of the bundled one |

```
target
├── ebpf
│   ├── KprobeConnectHook.bpf.o
│   └── TcFilter.bpf.o
├── include
│   ├── Common.h
│   ├── KprobeLoader.h
│   ├── TcLoader.h
│   └── UpdateMaps.h
├── libeBPF.a
└── test
    └── BPFTcFilterTests
```

## Directory layout:

- `contrib/` external dependencies, libraries
  - `contrib/elftoolchain` repo: [github.com/elftoolchain/elftoolchain@11d16eab](https://github.com/elftoolchain/elftoolchain/commit/11d16eab)
  - `contrib/kernel_hdrs` headers with eBPF definitions, copied 1:1 from kernel sources
  - `contrib/libbpf` repo: [github.com/libbpf/libbpf@0.7.0](https://github.com/libbpf/libbpf/releases/tag/v0.7.0)
  - `contrib/googletest` repo: [github.com/google/googletest@955c7f83](https://github.com/google/googletest/commit/955c7f83)
- `GPL` eBPF programs which are GPL licensed
- `non-GPL` tools, utilities with Elastic non-GPL license
