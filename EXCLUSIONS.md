elastic/ebpf is tested against a matrix of kernels. The code contained in this
repository is intended for use with linux kernel version 5.10.16 or higher,
with BTF (and other requisite configs) enabled.

The following is a list of kernels where the ebpf programs fail to load or
cannot be tested with our test infrastructure. This list has been created
through empirical testing, and is not exhaustive.

## Excluded Kernels

### BTF unavailable

    linux-image-x86_64-5.11.0-1013-oracle
    linux-image-x86_64-5.11.0-1016-oracle
    linux-image-x86_64-5.11.0-1017-oracle
    linux-image-x86_64-5.11.0-1019-oracle
    linux-image-x86_64-5.11.0-1020-oracle
    linux-image-x86_64-5.11.0-1021-oracle
    linux-image-x86_64-5.11.0-1022-oracle
    linux-image-x86_64-5.11.0-1023-oracle
    linux-image-x86_64-5.11.0-1025-oracle
    linux-image-aarch64-5.11.0-1016-oracle
    linux-image-aarch64-5.11.0-1017-oracle
    linux-image-aarch64-5.11.0-1019-oracle
    linux-image-aarch64-5.11.0-1020-oracle
    linux-image-aarch64-5.11.0-1021-oracle
    linux-image-aarch64-5.11.0-1022-oracle
    linux-image-aarch64-5.11.0-1023-oracle
    linux-image-aarch64-5.11.0-1025-oracle
    linux-image-x86_64-5.13.0-1009-oem
    linux-image-x86_64-5.13.0-1010-oem
    linux-image-x86_64-5.13.0-1012-oem
    linux-image-x86_64-5.13.0-1014-oem
    linux-image-x86_64-5.13.0-1017-oem
    linux-image-x86_64-5.13.0-1019-oem
    linux-image-x86_64-5.13.0-1020-oem
    linux-image-x86_64-5.13.0-1022-oem
    linux-image-x86_64-5.13.0-1026-oem
    linux-image-x86_64-5.13.0-1029-oem
    linux-image-x86_64-5.14.0-1004-oem
    linux-image-x86_64-5.14.0-1005-oem
    linux-image-x86_64-5.14.0-1008-oem
    linux-image-x86_64-5.14.0-1010-oem
    linux-image-x86_64-5.14.0-1011-oem
    linux-image-x86_64-5.14.0-1013-oem
    linux-image-x86_64-5.14.0-1018-oem
    linux-image-x86_64-5.14.0-1020-oem
    linux-image-x86_64-5.14.0-1022-oem
    linux-image-x86_64-5.14.0-1024-oem
    linux-image-x86_64-5.14.0-1029-oem
    linux-image-x86_64-5.14.0-1031-oem
    linux-image-x86_64-5.14.0-1032-oem
    linux-image-x86_64-5.14.0-1033-oem
    linux-image-x86_64-5.14.0-1034-oem
    linux-image-x86_64-5.14.0-1036-oem
    linux-image-x86_64-5.14.0-1038-oem
    linux-image-x86_64-5.14.0-1042-oem
    linux-image-x86_64-5.14.0-1044-oem
    linux-image-x86_64-5.14.0-1045-oem
    linux-image-x86_64-5.14.0-1046-oem
    linux-image-x86_64-5.14.0-1047-oem
    linux-image-x86_64-5.14.0-1048-oem
    linux-image-x86_64-5.11.0-1009-gcp
    linux-image-x86_64-5.11.0-1017-gcp
    linux-image-x86_64-5.11.0-1020-gcp
    linux-image-x86_64-5.11.0-1021-gcp
    linux-image-x86_64-5.11.0-1022-gcp
    linux-image-x86_64-5.11.0-1023-gcp
    linux-image-x86_64-5.11.0-1024-gcp
    linux-image-x86_64-5.11.0-1026-gcp
    linux-image-x86_64-5.11.0-1028-gcp
    linux-image-x86_64-5.11.0-1012-azure
    linux-image-x86_64-5.11.0-1013-azure
    linux-image-x86_64-5.11.0-1015-azure
    linux-image-x86_64-5.11.0-1017-azure
    linux-image-x86_64-5.11.0-1019-azure
    linux-image-x86_64-5.11.0-1020-azure
    linux-image-x86_64-5.11.0-1022-azure
    linux-image-x86_64-5.11.0-1025-azure

### Serial Port Unavailable

The following kernels compile the serial driver as a module, which does not
work with our test setup (it must be builtin)

```
linux-image-aarch64-5.13.0-1011-oracle
linux-image-aarch64-5.13.0-1015-oracle
linux-image-aarch64-5.13.0-1016-oracle
linux-image-aarch64-5.13.0-1018-oracle
```
