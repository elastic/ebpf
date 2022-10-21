<img alt="elastic-loves-ebpf" src="https://user-images.githubusercontent.com/8242268/184464400-f485dfab-c4c1-49d2-850e-d419256bdecc.png">

[![CI](https://github.com/elastic/ebpf/actions/workflows/ci.yml/badge.svg)](https://github.com/elastic/ebpf/actions/workflows/ci.yml)

This repository contains eBPF code as well as associated userspace tools and
components used in the Linux build of [Elastic Endpoint
Security](https://www.elastic.co/security/endpoint-security).

Elastic Endpoint on Linux currently leverages eBPF for two use-cases: host
isolation and event sourcing, with all code pertaining to the two being hosted
here. At a high level, this repository is divided up on licensing grounds. eBPF
code, which must be GPL-licensed for the kernel to accept and load it, is
located under the `GPL/` directory while all non-GPL code is located under the
`non-GPL` directory.

## Event Sourcing

On newer kernels (5.10.16+), Elastic endpoint uses eBPF to source the various
security events it ultimately sends up to an Elasticsearch cluster (e.g.
process execution, file creation, file rename). On older kernels, this data is
sourced via
[tracefs](https://www.kernel.org/doc/Documentation/trace/ftrace.txt) instead.

Event sourcing eBPF code is found under `GPL/Events` and associated userspace
tools can be found under `non-GPL/Events`. See [docs/events.md](docs/events.md)
for detailed information on the event sourcing code.

## Host Isolation

[Host
isolation](https://www.elastic.co/guide/en/security/current/host-isolation-api.html)
is essentially an incredibly strict firewall that allows only Elastic Endpoint
to communicate with the outside world. It can be manually enabled in Kibana and
is meant be used in cases where a host is known or suspected to be compromised,
allowing security teams more time to locate the threat at hand.

Host isolation eBPF code is found under `GPL/HostIsolation` and associated userspace
tools can be found under `non-GPL/HostIsolation`. See
[docs/hostisolation.md](docs/hostisolation.md) for detailed information on the
host isolation code.

## Building

To build all artifacts in the repository, run:

```
make build ARCH=<arch>
```

Where `arch` is one of `x86_64` or `aarch64`. The build is run in a docker
container with all required dependencies bundled inside.

## Repository Layout

```
.
|-- GPL                              # Dual BSD/GPLv2-licensed sources (mainly eBPF code)
|   |-- Events                       # Event sourcing eBPF code
|   |   |-- File                     # Code to source file events
|   |   |-- Network                  # eBPF code to source network events
|   |   `-- Process                  # eBPF code to source process events
|   `-- HostIsolation                # Host isolation eBPF code and tests
|       |-- KprobeConnectHook
|       `-- TcFilter
|-- cmake
|   `-- modules                      # CMake modules to build third party dependencies
|-- contrib                          # Third party dependency sources
|   |-- elftoolchain
|   |-- googletest
|   |-- kernel_hdrs                  # Kernel headers used in HostIsolation eBPF code (copied from kernel)
|   |-- libbpf
|   `-- vmlinux                      # bpftool-generated vmlinux.h (see contrib/vmlinux/README.md)
|       |-- aarch64
|       `-- x86_64
|-- docker                           # Dockerfiles used to build/test
|-- licenses                         # Licenses used in the codebase
|-- non-GPL                          # Elastic-2.0 licensed code (userspace tools and libraries)
|   |-- Events                       # Userspace tools and libraries related to event sourcing
|   |   |-- EventsTrace              # Simple command-line utility to load and use event probes
|   |   |-- Lib                      # Userspace library to load and use event probes used by EventsTrace
|   `-- HostIsolation                # Userspace tools and libraries related to host isolation
|       |-- Demos                    # Demo binaries for the various, granular parts of host isolation
|       `-- Lib                      # Userspace library that allows for use of host isolation functionality
`-- testing                          # Infrastructure to test eBPF code on many kernels (see testing/README.md)
```

## Testing

This repository contains infrastructure to test our eBPF code against a wide
array of kernels. See [testing/README.md](testing/README.md) for more
information. For more details on kernels that are excluded from testing, see [EXCLUSIONS.md](EXCLUSIONS.md)

## Licensing

Various licenses are used in this repository, see the [LICENSE.txt](LICENSE.txt) file for details.
