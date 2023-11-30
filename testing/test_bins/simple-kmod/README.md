# simple-kmod

Simple kmod example taken from [tldp.org](https://www.tldp.org/LDP/lkmpg/2.6/html/x121.html).

To build on Fedora, first install:

```
sudo dnf install kernel-devel make gcc
```

To build for the currently running kernel use:

```
make all
```

To build for a specific kernel:

```
make all KVER=5.3.4-300.fc31.x86_64
```

Load module:

```
sudo insmod hello-1.ko
```
