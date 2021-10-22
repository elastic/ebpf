# ebpf

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

#### Run Demos

1. Follow the build section to build the project so that you have the `build/` folder
1. Run `cd GPL/HostIsolation/TcFilter`
1. Run `sudo ../../../non-GPL/TcLoader/TcLoaderDemo` - packet filter is now attached to ens33
1. Run `cd ../../../GPL/HostIsolation/KprobeConnectHook`
1. Run `sudo ../../../non-GPL/HostIsolation/KprobeConnectHook/KprobeConnectHookDemo` - connect hook is attached
1. Run `firefox` in another tab - verify that all internet access is blocked
1. Run `pgrep firefox` to get the PID of the browser
1. Run `cd ../../../`
1. Run `sudo non-GPL/HostIsolationMapsUtil/UpdatePidsDemo <firefox PID>`
1. Verify that firefox connects to any page
1. Quit KprobeConnectHook with Ctrl+C and run `sudo ./non-GPL/TcLoader/TcLoaderDemo unload` to detach both eBPF programs

### Tests (BPF_PROG_TEST_RUN)

#### BPFTcFilterTests

`BPFTcFilterTests` test suite for the `TcFilter.bpf.o` program

**Usage**

```bash
cd build/GPL/HostIsolation/TcFilter
sudo ../TcFilter/BPFTcFilterTests
```

Or if you want to use a custom path for the eBPF object file.

```bash
sudo ELASTIC_EBPF_TC_FILTER_OBJ_PATH=build/GPL/HostIsolation/TcFilter/TcFilter.bpf.o  build/GPL/HostIsolation/TcFilter/BPFTcFilterTest
```

## Build

Build dependencies

```
apt install clang llvm cmake bmake zlib1g-dev m4 gcc g++
```

The build is a pretty standard CMake project.

```
mkdir build
cd build
cmake ..
make
make install
```

After doing `make install`, the final artifacts  will be installed in `build/target`.

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
  - `contrib/libbpf` repo: [github.com/libbpf/libbpf@767d82ca](https://github.com/libbpf/libbpf/commit/767d82ca)
  - `contrib/googletest` repo: [github.com/google/googletest@955c7f83](https://github.com/google/googletest/commit/955c7f83)
- `GPL` eBPF programs which are GPL licensed
- `non-GPL` tools, utilities with Elastic non-GPL license
