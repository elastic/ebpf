# vmlinux

**Nota Bene**: This is a temporary workaround we are using because our build
fleet is on an a kernel that was not built with `CONFIG_DEBUG_INFO_BTF`.
Using this `vmlinux.h` *IS NOT* the default, our CI uses the `-DUSE_BUILTIN_VMLINUX=True`
flag to make use of this.


## Updates

To update the content of this folder, on a machine with a kernel compiled with `CONFIG_DEBUG_INFO_BTF=y`.

```
cd build/
make vmlinux
cp vmlinux/vmlinux.h ../contrib/vmlinux/vmlinux.h
```
