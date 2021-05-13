# ebpf
eBPF code for Endpoint

Directory layout:

    contrib - external dependencies, libraries

    contrib/elftoolchain - copied repo: github.com/elftoolchain/elftoolchain @ 11d16eab

    contrib/kernel_hdrs - headers with eBPF definitions, copied 1:1 from kernel sources

    contrib/libbpf - copied repo: github.com/libbpf/libbpf @ 767d82ca

    contrib/patch - .patch files to apply to imported code (mostly elftoolchain)

    GPL - eBPF programs which are GPL licensed

    non-GPL - tools, utilities with Elastic non-GPL license

    build_demos.sh - build script for demo build 

    build_lib.sh - build script for static library

    clean.sh - script cleaning all build output

---------------------------------------------------------
eBPF programs consist of:
    
    KprobeConnectHook - hooks into tcp_v4_connect and adds destination IP to allowlist if PID is allowed

    TcFilter - attaches to network interface and filters packets based on allowed IPs

Tools and loaders consist of:

    UpdateIPsDemo - Userspace tool for updating IP allowlist

    UpdatePidsDemo - Userspace tool for updating PID allowlist

    KprobeConnectHookDemo - Loader for KprobeConnectHook eBPF program

    TcLoaderDemo - Loader for TcFilter eBPF program, attaches to ens33 interface by default
    
---------------------------------------------------------
How to run Host Isolation demo:

    1. run `build_demos.sh`

    2. copy TcFilter.bpf.o to the same directory as TcLoaderDemo

    3. run `sudo ./TcLoaderDemo` - packet filter is now attached to ens33

    4. run `sudo ./KprobeConnectHookDemo` - connect hook is attached

    5. run `firefox` in another tab - verify that all internet access is blocked

    6. run `pgrep firefox` to get the PID of the browser

    7. run `sudo ./UpdatePidsDemo <firefox PID>`

    8. verify that firefox connects to any page

    9. quit KprobeConnectHook with Ctrl+C and run `sudo ./TcLoaderDemo unload` to detach both eBPF programs

