# Host Isolation

eBPF-based host isolation consists of two BPF programs:

- **KprobeConnectHook** hooks into tcp_v4_connect and adds
  destination IP to allowlist if the PID has been marked as allowed
- **TcFilter** attaches to network interfaces and filters packets
  based on allowed IPs set by KprobeConnectHook

## Local Usage

The following demo binaries are located at `non-GPL/HostIsolation/Demos` and
allow for host isolation to be tested/demoed locally without the use of Elastic
Endpoint:

- **UpdateIPsDemo** Userspace tool for updating IP and subnet allowlist
- **UpdatePidsDemo** Userspace tool for updating PID allowlist
- **KprobeConnectHookDemo** Loader for the KprobeConnectHook eBPF program
- **TcLoaderDemo** Loader for the TcFilter eBPF program, attaches to ens33 interface by default

These binaries can be used to demo/test host isolation locally as follows:

1. Build the repository
2. Run `cd <build directory>/target/ebpf`
3. Run `sudo ../../non-GPL/TcLoader/TcLoaderDemo` - packet filter is now attached to ens33
4. Run `sudo ../../non-GPL/HostIsolation/KprobeConnectHook/KprobeConnectHookDemo` - connect hook is attached
5. Run `firefox` in another tab - verify that all internet access is blocked
6. Run `pgrep firefox` to get the PID of the browser
7. Run `sudo ../../non-GPL/HostIsolationMapsUtil/UpdatePidsDemo <firefox PID>`
8. Verify that firefox connects to any page
9. Quit KprobeConnectHook with Ctrl+C and run `sudo ../../non-GPL/TcLoader/TcLoaderDemo unload` to detach both eBPF programs

## Tests

Tests for host isolation based off the `BPF_PROG_RUN` command to the `bpf`
syscall are located at `GPL/HostIsolation/TcFilter`. They can be invoked as
follows:

```bash
cd <build dir>/target/ebpf
sudo ../test/BPFTcFilterTests
```

Or if you want to use a custom path for the eBPF object file.

```bash
sudo ELASTIC_EBPF_TC_FILTER_OBJ_PATH=<build dir>/target/ebpf/TcFilter.bpf.o  <build dir>/target/test/BPFTcFilterTests
```
